"""Checked JSON manifest boundary for independent real16 differential replay.

Layer: dosunit CLI/execution reporting.
Responsibility: own the manifest contract — every JSON shape check, numeric
width check and enum admission for the declared segmented vectors, per-side
load paragraphs and explicit code ranges. Parsing completes for the whole
selection before any binary is read or guest executes, so a malformed vector
can never produce a partial report. Nothing is inferred: frames, pointers,
registers, observables and code ranges must be declared, and every refusal
carries its cause in ``DosUnitError``.

"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.runtime.real16_mz_load import DEFAULT_LOAD_SEGMENT
from tools.dosunit.runtime.real16_replay_model import (
    FLAG_OBSERVABLES,
    GENERAL_REGS,
    HIGH_REGS,
    PRESERVED_OBSERVABLES,
    SEGMENT_REGS,
    VECTOR_SEGMENTS,
    CallerFrame,
    FrameKind,
    LinearRange,
    Real16Vector,
    SegOffset,
)

_FRAME_KINDS: str = "'near16' or 'far16'"


@dataclass(frozen=True, slots=True)
class Real16ManifestVector:
    """One fully checked vector bound to both side entry contracts.

    ``observables`` is the declared narrowing set for comparison, or ``None``
    when the vector does not declare one and the default contract applies.
    """

    vector_id: str
    oracle_entry: SegOffset
    candidate_entry: SegOffset
    vector: Real16Vector
    observables: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class Real16Manifest:
    """Fully checked replay selection parsed before any execution.

    ``*_code_ranges`` are the declared physical instruction-byte ranges for
    that side, or ``None`` when the manifest leaves the whole relocated image
    executable (recorded as ``whole_image`` scope by the loader).
    """

    oracle_load_segment: int
    candidate_load_segment: int
    oracle_code_ranges: tuple[LinearRange, ...] | None
    candidate_code_ranges: tuple[LinearRange, ...] | None
    vectors: tuple[Real16ManifestVector, ...]


def _int_value(value: object, field: str) -> int:
    """Parse an explicit non-negative integer; bools and floats refuse."""
    if type(value) is int:
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as error:
            raise DosUnitError(f"{field}: invalid integer {value!r}") from error
    else:
        raise DosUnitError(f"{field}: expected integer or hexadecimal string")
    if parsed < 0:
        raise DosUnitError(f"{field}: value must be non-negative")
    return parsed


def _u16(value: object, field: str) -> int:
    """Parse a checked 16-bit quantity, rejecting truncation."""
    parsed = _int_value(value, field)
    if parsed > 0xFFFF:
        raise DosUnitError(f"{field}: value does not fit 16 bits")
    return parsed


def _u32(value: object, field: str) -> int:
    """Parse a checked 32-bit quantity, rejecting truncation."""
    parsed = _int_value(value, field)
    if parsed > 0xFFFFFFFF:
        raise DosUnitError(f"{field}: value does not fit 32 bits")
    return parsed


def _seg_offset(raw: object, field: str) -> SegOffset:
    """Parse one declared ``{segment, offset}`` address; nothing is inferred."""
    if not isinstance(raw, dict):
        raise DosUnitError(f"{field}: expected an object with segment and offset")
    return SegOffset(
        _u16(raw.get("segment"), f"{field}.segment"),
        _u16(raw.get("offset"), f"{field}.offset"),
    )


def _frame(raw: object, field: str) -> CallerFrame:
    """Parse the declared caller frame; other frame kinds are refused."""
    if not isinstance(raw, dict):
        raise DosUnitError(f"{field}: expected a frame object with kind and target")
    kind = raw.get("kind")
    if not isinstance(kind, str):
        raise DosUnitError(f"{field}.kind: expected {_FRAME_KINDS}")
    try:
        frame_kind = FrameKind(kind)
    except ValueError as error:
        raise DosUnitError(f"{field}.kind: expected {_FRAME_KINDS}") from error
    guard = raw.get("sp_guard", False)
    if not isinstance(guard, bool):
        raise DosUnitError(f"{field}.sp_guard: expected a boolean")
    return CallerFrame(
        frame_kind, _seg_offset(raw.get("target"), f"{field}.target"), guard
    )


def _name_map(raw: object, field: str, allowed: set[str]) -> tuple[tuple[str, int], ...]:
    """Parse a ``{name: u16}`` object restricted to declared register names."""
    if not isinstance(raw, dict):
        raise DosUnitError(f"{field}: expected an object of register names")
    if not all(isinstance(name, str) for name in raw):
        raise DosUnitError(f"{field}: register names must be strings")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise DosUnitError(f"{field}: unsupported register names {unknown}")
    return tuple(
        (name, _u16(value, f"{field}.{name}"))
        for name, value in sorted(raw.items())
    )


def _memory_patches(raw: object, field: str) -> tuple[tuple[SegOffset, bytes], ...]:
    """Read explicit concrete segmented patch bytes; empty payloads refuse."""
    if not isinstance(raw, list):
        raise DosUnitError(f"{field}: expected a list of memory patches")
    patches: list[tuple[SegOffset, bytes]] = []
    for index, item in enumerate(raw):
        item_field = f"{field}[{index}]"
        if not isinstance(item, dict):
            raise DosUnitError(f"{item_field}: expected a patch object")
        data_raw = item.get("bytes")
        if not isinstance(data_raw, str):
            raise DosUnitError(f"{item_field}.bytes: expected a hexadecimal string")
        try:
            data = bytes.fromhex(data_raw)
        except ValueError as error:
            raise DosUnitError(f"{item_field}.bytes: invalid hexadecimal bytes") from error
        if not data:
            raise DosUnitError(f"{item_field}.bytes: patch bytes cannot be empty")
        patches.append((_seg_offset(item, item_field), data))
    return tuple(patches)


def _observation_ranges(raw: object, field: str) -> tuple[tuple[SegOffset, int], ...]:
    """Read declared segmented observation ranges; zero sizes refuse."""
    if not isinstance(raw, list):
        raise DosUnitError(f"{field}: expected a list of observations")
    ranges: list[tuple[SegOffset, int]] = []
    for index, item in enumerate(raw):
        item_field = f"{field}[{index}]"
        if not isinstance(item, dict):
            raise DosUnitError(f"{item_field}: expected an observation object")
        size = _u32(item.get("size"), f"{item_field}.size")
        if size == 0:
            raise DosUnitError(f"{item_field}.size: observation size must be positive")
        ranges.append((_seg_offset(item, item_field), size))
    return tuple(ranges)


def _observables(raw: object, field: str) -> tuple[str, ...]:
    """Read an explicitly declared observable set; empty/duplicate refuse."""
    if not isinstance(raw, list) or not raw:
        raise DosUnitError(f"{field}: expected a nonempty list of register names")
    names = tuple(name for name in raw if isinstance(name, str))
    if len(names) != len(raw):
        raise DosUnitError(f"{field}: observable names must be strings")
    if len(set(names)) != len(names):
        raise DosUnitError(f"{field}: duplicate observable names")
    known = set(GENERAL_REGS) | set(HIGH_REGS) | set(SEGMENT_REGS) | FLAG_OBSERVABLES | {"ip"}
    unknown = sorted(set(names) - known)
    if unknown:
        raise DosUnitError(f"{field}: unsupported observable names {unknown}")
    if not set(names) >= PRESERVED_OBSERVABLES:
        raise DosUnitError(
            f"{field}: observables must retain the caller-owned preserved set"
        )
    return names


def _vector(
    item: dict[str, object], field: str,
) -> tuple[SegOffset, SegOffset, Real16Vector, tuple[str, ...] | None]:
    """Convert one checked JSON vector to the owned execution contract."""
    oracle_entry = _seg_offset(item.get("oracle_entry"), f"{field}.oracle_entry")
    candidate_entry = _seg_offset(item.get("candidate_entry"), f"{field}.candidate_entry")
    try:
        vector = Real16Vector(
            registers=_name_map(
                item.get("registers"), f"{field}.registers",
                set(GENERAL_REGS) | {"flags"},
            ),
            segments=_name_map(
                item.get("segments"), f"{field}.segments", set(VECTOR_SEGMENTS),
            ),
            frame=_frame(item.get("frame"), f"{field}.frame"),
            high_halves=_name_map(
                item.get("high_halves", {}), f"{field}.high_halves",
                set(HIGH_REGS) | {"eflags"},
            ),
            memory=_memory_patches(item.get("memory", []), f"{field}.memory"),
            observations=_observation_ranges(
                item.get("observations", []), f"{field}.observations",
            ),
            flags_mask=_u32(item.get("flags_mask", 0), f"{field}.flags_mask"),
        )
    except ValueError as error:
        raise DosUnitError(f"{field}: {error}") from error
    raw_observables = item.get("observables")
    observables = (
        None
        if raw_observables is None
        else _observables(raw_observables, f"{field}.observables")
    )
    return oracle_entry, candidate_entry, vector, observables


def _checked_vector_items(document: dict[str, object]) -> list[tuple[str, dict[str, object], str]]:
    """Reject empty, ambiguous or malformed selections before loading binaries."""
    raw = document.get("vectors")
    if not isinstance(raw, list) or not raw:
        raise DosUnitError("real16 replay needs a nonempty vectors list")
    checked: list[tuple[str, dict[str, object], str]] = []
    ids: set[str] = set()
    for index, item in enumerate(raw):
        field = f"vectors[{index}]"
        vector_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(vector_id, str) or not vector_id:
            raise DosUnitError(f"{field}: every real16 vector requires a nonempty id")
        if vector_id in ids:
            raise DosUnitError(f"{field}: duplicate real16 vector id {vector_id!r}")
        ids.add(vector_id)
        checked.append((vector_id, item, field))
    return checked


def _load_segment(document: dict[str, object], side: str) -> int:
    """Parse one side's declared load paragraph; absent uses the default."""
    return _u16(
        document.get(f"{side}_load_segment", DEFAULT_LOAD_SEGMENT),
        f"{side}_load_segment",
    )


def _code_ranges(document: dict[str, object], side: str) -> tuple[LinearRange, ...] | None:
    """Parse one side's explicit physical code ranges; an empty list refuses."""
    raw = document.get(f"{side}_code_ranges")
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw:
        raise DosUnitError(f"{side}_code_ranges: expected a nonempty list of ranges")
    ranges: list[LinearRange] = []
    for index, item in enumerate(raw):
        item_field = f"{side}_code_ranges[{index}]"
        if not isinstance(item, dict):
            raise DosUnitError(f"{item_field}: expected a range object")
        try:
            ranges.append(
                LinearRange(
                    _u32(item.get("address"), f"{item_field}.address"),
                    _u32(item.get("size"), f"{item_field}.size"),
                )
            )
        except ValueError as error:
            raise DosUnitError(f"{item_field}: {error}") from error
    return tuple(ranges)


def parse_manifest(document: object) -> Real16Manifest:
    """Parse the whole checked manifest before any binary load or execution.

    Every vector is converted to its typed contract up front, so malformed
    selections refuse without producing a partial report. The returned value
    is the single authoritative projection of the JSON document for the CLI.
    """
    if not isinstance(document, dict):
        raise DosUnitError("real16 replay manifest must be an object")
    items = _checked_vector_items(document)
    vectors = tuple(
        Real16ManifestVector(vector_id, *_vector(item, field))
        for vector_id, item, field in items
    )
    return Real16Manifest(
        oracle_load_segment=_load_segment(document, "oracle"),
        candidate_load_segment=_load_segment(document, "candidate"),
        oracle_code_ranges=_code_ranges(document, "oracle"),
        candidate_code_ranges=_code_ranges(document, "candidate"),
        vectors=vectors,
    )


__all__ = [
    "Real16Manifest",
    "Real16ManifestVector",
    "parse_manifest",
]
