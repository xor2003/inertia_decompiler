from __future__ import annotations  # noqa: D100

import hashlib
import json
from pathlib import Path
from typing import Any


class DosUnitError(RuntimeError):
    """Raised for user-facing dosunit input errors."""


GENERAL_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip", "flags")
SEGMENT_REGS = ("cs", "ds", "es", "ss", "fs", "gs")
MEMORY_SPACES = ("CS", "DS", "ES", "SS", "FS", "GS", "SEG", "LINEAR")
STATUS_VALUES = {
    "passed",
    "failed",
    "refused",
    "timeout",
    "faulted",
    "unsupported",
    "backend_error",
}
VERDICT_VALUES = {
    "equivalent",
    "observable_mismatch",
    "oracle_unavailable",
    "candidate_unavailable",
    "mapping_unavailable",
    "unsupported_effect",
    "nondeterministic",
    "backend_failure",
}
REFUSAL_REASONS = {
    "unsupported_ir",
    "unsupported_effect",
    "unbounded_memory",
    "unbounded_indirect_control",
    "segment_unresolved",
    "mapping_ambiguous",
    "mapping_missing",
    "trap_unavailable",
    "call_unmodeled",
    "device_io_unmodeled",
    "dos_interrupt_unmodeled",
    "timeout",
    "backend_error",
    "oracle_unavailable",
}


def parse_int(value: object, *, field: str = "value") -> int:  # noqa: D103
    if isinstance(value, bool):
        raise DosUnitError(f"{field} must be an integer or hex string")
    if isinstance(value, int):
        if value < 0:
            raise DosUnitError(f"{field} must be non-negative")
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "auto":
            raise DosUnitError(f"{field} is auto, not a concrete integer")
        try:
            return int(text, 0)
        except ValueError as ex:
            raise DosUnitError(f"{field} is not an integer: {value!r}") from ex
    raise DosUnitError(f"{field} must be an integer or hex string")


def normalize_hex(value: object, *, width: int | None = None, field: str = "value") -> str:  # noqa: D103
    number = parse_int(value, field=field)
    if width is None:
        return f"0x{number:x}"
    mask = (1 << (width * 4)) - 1
    if number > mask:
        raise DosUnitError(f"{field} does not fit in {width} hex digits: {value!r}")
    return f"0x{number:0{width}x}"


def normalize_auto_hex(value: object, *, width: int | None = None, field: str = "value") -> str:  # noqa: D103
    if isinstance(value, str) and value.strip().lower() == "auto":
        return "auto"
    return normalize_hex(value, width=width, field=field)


def canonical_json_bytes(value: object) -> bytes:  # noqa: D103
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def stable_id(prefix: str, value: object) -> str:  # noqa: D103
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"{prefix}:{digest}"


def load_json(path: Path) -> Any:  # noqa: ANN401, D103
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as ex:
        raise DosUnitError(f"failed to parse JSON {path}: {ex}") from ex


def write_json(path: Path, value: object) -> None:  # noqa: D103
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def require_mapping(value: object, *, field: str) -> dict[str, Any]:  # noqa: D103
    if not isinstance(value, dict):
        raise DosUnitError(f"{field} must be an object")
    return value


def require_list(value: object, *, field: str) -> list[Any]:  # noqa: D103
    if not isinstance(value, list):
        raise DosUnitError(f"{field} must be an array")
    return value


def vectors_from_document(document: object) -> list[dict[str, Any]]:  # noqa: D103
    root = require_mapping(document, field="vectors document")
    if root.get("schema") == "dosunit.vector.v1":
        return [root]
    vectors = require_list(root.get("vectors"), field="vectors")
    return [require_mapping(item, field=f"vectors[{idx}]") for idx, item in enumerate(vectors)]


def _normalize_pre_regs(pre: dict[str, Any]) -> None:
    """Validate and normalize pre-state register values."""
    regs = require_mapping(pre.setdefault("regs", {}), field="pre.regs")
    for reg in tuple(regs):
        if reg not in GENERAL_REGS:
            raise DosUnitError(f"unsupported register in pre.regs: {reg}")
        regs[reg] = normalize_hex(regs[reg], width=4, field=f"pre.regs.{reg}")

    sregs = require_mapping(pre.setdefault("sregs", {}), field="pre.sregs")
    for reg in tuple(sregs):
        if reg not in SEGMENT_REGS:
            raise DosUnitError(f"unsupported segment register in pre.sregs: {reg}")
        sregs[reg] = normalize_auto_hex(sregs[reg], width=4, field=f"pre.sregs.{reg}")


def _normalize_pre_memory_item(mem: dict[str, Any], idx: int) -> None:
    """Validate and normalize one pre-state memory byte-range entry."""
    space = str(mem.get("space", "")).upper()
    if space not in MEMORY_SPACES:
        raise DosUnitError(f"unsupported memory space in pre.memory[{idx}]: {space!r}")
    mem["space"] = space
    if space == "SEG":
        mem["segment"] = normalize_hex(mem.get("segment"), width=4, field=f"pre.memory[{idx}].segment")
    if "offset" in mem:
        mem["offset"] = normalize_hex(mem["offset"], width=4, field=f"pre.memory[{idx}].offset")
    if "linear" in mem:
        mem["linear"] = normalize_hex(mem["linear"], field=f"pre.memory[{idx}].linear")
    bytes_text = mem.get("bytes", "")
    if not isinstance(bytes_text, str) or len(bytes_text) % 2 != 0:
        raise DosUnitError(f"pre.memory[{idx}].bytes must be an even-length hex string")
    try:
        bytes.fromhex(bytes_text)
    except ValueError as ex:
        raise DosUnitError(f"pre.memory[{idx}].bytes is not hex") from ex
    mem["bytes"] = bytes_text.lower()


def _normalize_observe(observe: dict[str, Any]) -> None:
    """Validate and normalize the observation contract fields."""
    observe.setdefault("regs", [])
    observe.setdefault("sregs", [])
    observe.setdefault("memory", [])
    for reg in require_list(observe["regs"], field="observe.regs"):
        if reg not in GENERAL_REGS:
            raise DosUnitError(f"unsupported observe register: {reg}")
    for reg in require_list(observe["sregs"], field="observe.sregs"):
        if reg not in SEGMENT_REGS:
            raise DosUnitError(f"unsupported observe segment register: {reg}")
    if "flags_mask" in observe:
        observe["flags_mask"] = normalize_hex(observe["flags_mask"], width=4, field="observe.flags_mask")




def normalize_vector(vector: dict[str, Any]) -> dict[str, Any]:  # noqa: D103
    normalized: dict[str, Any] = json.loads(json.dumps(vector))
    normalized["schema"] = "dosunit.vector.v1"

    pre = require_mapping(normalized.setdefault("pre", {}), field="pre")
    _normalize_pre_regs(pre)

    memory = require_list(pre.setdefault("memory", []), field="pre.memory")
    for idx, item in enumerate(memory):
        mem = require_mapping(item, field=f"pre.memory[{idx}]")
        _normalize_pre_memory_item(mem, idx)

    observe = require_mapping(normalized.setdefault("observe", {}), field="observe")
    _normalize_observe(observe)

    without_expected = json.loads(json.dumps(normalized))
    without_expected.pop("expected", None)
    without_expected.pop("id", None)
    normalized["id"] = stable_id("vector", without_expected)
    normalized.setdefault("expected", None)
    return normalized


def compare_observations(  # noqa: D103
    expected: dict[str, Any], candidate: dict[str, Any], *, ignore_fields: set[str] | None = None
) -> tuple[bool, list[str]]:
    changed: list[str] = []
    ignored = ignore_fields or set()
    for field in ("status", "regs", "sregs", "flags", "memory", "return", "calls"):
        if field in ignored:
            continue
        if expected.get(field) != candidate.get(field):
            changed.append(field)
    return not changed, changed


def refusal(reason: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:  # noqa: D103
    if reason not in REFUSAL_REASONS:
        raise DosUnitError(f"unsupported refusal reason: {reason}")
    return {"status": "refused", "reason": reason, "detail": detail or {}}
