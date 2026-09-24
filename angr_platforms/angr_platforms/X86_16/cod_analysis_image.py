"""Build relocatable analysis images from optional COD instruction rows.

Layer: Frontend.
Responsibility: preserve listed instruction bytes while reconstructing exact
internal call relocations or assigning synthetic external-call targets when
the linker relocations are absent from COD.
The resulting labels are optional naming evidence; call arguments and effects
must still be recovered from binary IR and typed pipeline facts.
Module images consume direct-call labels only as relocation identity. Assembly
and source comments must never supply semantic, control-flow, or type evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .cod_extract import CODListingMetadata, join_cod_entries_with_synthetic_globals
from .cod_known_objects import canonical_known_cod_object_name

__all__ = [
    "CODAnalysisImage8616",
    "CODModuleAnalysisImage8616",
    "build_cod_analysis_image_8616",
    "build_cod_module_analysis_image_8616",
]

_DIRECT_NEAR_CALL_RE = re.compile(r"\bcall\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\b", re.IGNORECASE)
_DIRECT_FAR_CALL_RE = re.compile(
    r"\bcall\s+far\s+ptr\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\b",
    re.IGNORECASE,
)
_INSTRUCTION_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF2, 0xF3})


@dataclass(frozen=True, slots=True)
class CODAnalysisImage8616:
    """One synthetic COD code image plus proven labels for its storage."""

    code: bytes
    synthetic_globals: dict[int, tuple[str, int]]
    call_target_offsets: dict[int, str]


@dataclass(frozen=True, slots=True)
class CODModuleAnalysisImage8616:
    """Byte-faithful COD module image and its independently bounded functions."""

    code: bytes
    original_base_offset: int
    function_ranges: tuple[tuple[int, int], ...]
    instruction_row_count: int

    def analysis_addr(self, original_offset: int, *, image_base: int) -> int:
        """Map one original module offset into the synthetic analysis image."""
        return image_base + original_offset - self.original_base_offset

    def analysis_ranges(self, *, image_base: int) -> tuple[tuple[int, int], ...]:
        """Map all proven function ranges into the synthetic analysis image."""
        return tuple(
            (
                self.analysis_addr(start, image_base=image_base),
                self.analysis_addr(end, image_base=image_base),
            )
            for start, end in self.function_ranges
        )

    def original_addr(self, analysis_addr: int, *, image_base: int) -> int:
        """Map one synthetic analysis address back to its module offset."""
        return self.original_base_offset + analysis_addr - image_base


_COD_BYTE_ROW_RE = re.compile(
    r"\*\*\*\s+(?P<offset>[0-9A-Fa-f]+)\s+(?P<bytes>(?:[0-9A-Fa-f]{2}\s+)+)"
)


def _scan_cod_byte_rows_8616(
    cod_path: Path,
    function_ranges: tuple[tuple[int, int], ...],
    original_base: int,
    internal_targets: dict[str, int],
    image: bytearray,
    written: bytearray,
) -> tuple[list[tuple[int, int, int | None]], list[tuple[int, int, int | None]], int]:
    """Write COD byte rows into the image and collect unresolved call sites."""
    unresolved_near_calls: list[tuple[int, int, int | None]] = []
    unresolved_far_calls: list[tuple[int, int, int | None]] = []
    instruction_row_count = 0
    for line in cod_path.read_text(errors="ignore").splitlines():
        match = _COD_BYTE_ROW_RE.search(line)
        if match is None:
            continue
        offset = int(match.group("offset"), 16)
        data = bytes.fromhex("".join(match.group("bytes").split()))
        if not any(start <= offset and offset + len(data) <= end for start, end in function_ranges):
            continue
        cursor = offset - original_base
        for index, byte in enumerate(data):
            image_index = cursor + index
            if written[image_index] and image[image_index] != byte:
                raise ValueError(f"conflicting COD byte rows at module offset {offset + index:#x}")
            image[image_index] = byte
            written[image_index] = 1
        instruction_row_count += 1
        prefix_length = _near_call_prefix_length_8616(data)
        if prefix_length is not None and data[prefix_length + 1 : prefix_length + 3] == b"\x00\x00":
            call_match = _DIRECT_NEAR_CALL_RE.search(line)
            target_offset = (
                internal_targets.get(_canonical_call_name_8616(call_match.group("name")))
                if call_match is not None
                else None
            )
            unresolved_near_calls.append((cursor, prefix_length, target_offset))
        far_prefix_length = _far_call_prefix_length_8616(data)
        if far_prefix_length is not None and data[far_prefix_length + 1 : far_prefix_length + 5] == b"\x00" * 4:
            call_match = _DIRECT_FAR_CALL_RE.search(line)
            target_offset = (
                internal_targets.get(_canonical_call_name_8616(call_match.group("name")))
                if call_match is not None
                else None
            )
            unresolved_far_calls.append((cursor, far_prefix_length, target_offset))
    return unresolved_near_calls, unresolved_far_calls, instruction_row_count


def build_cod_module_analysis_image_8616(
    cod_path: Path,
    listing: CODListingMetadata,
    *,
    image_base: int = 0x10000,
) -> CODModuleAnalysisImage8616:
    """Build a complete module image from COD byte rows and proven bounds.

    Named unresolved calls to uniquely bounded module procedures receive their
    missing relocation. Other unresolved calls are redirected to synthetic
    return stubs so they cannot masquerade as calls to adjacent functions.
    Linked nonzero calls retain their exact bytes.
    """
    function_ranges = tuple(sorted(set(listing.code_ranges.values())))
    if not function_ranges:
        raise ValueError(f"COD listing has no bounded functions: {cod_path}")
    original_base = min(start for start, _end in function_ranges)
    original_end = max(end for _start, end in function_ranges)
    if original_end <= original_base or original_end - original_base > 0x10000:
        raise ValueError("COD module image must fit one 16-bit code segment")

    image = bytearray(b"\xcc" * (original_end - original_base))
    written = bytearray(len(image))
    label_offsets: dict[str, list[int]] = {}
    for offset, label in listing.code_labels.items():
        label_offsets.setdefault(_canonical_call_name_8616(label), []).append(offset)
    internal_targets = {
        name: offsets[0]
        for name, offsets in label_offsets.items()
        if len(offsets) == 1
    }

    unresolved_near_calls, unresolved_far_calls, instruction_row_count = _scan_cod_byte_rows_8616(
        cod_path, function_ranges, original_base, internal_targets, image, written,
    )
    if instruction_row_count == 0:
        raise ValueError(f"COD listing has no instruction byte rows: {cod_path}")
    near_sink_offset = len(image)
    far_sink_offset = near_sink_offset + 1
    image.extend(b"\xc3\xcb")
    for cursor, prefix_length, target_offset in unresolved_near_calls:
        displacement_offset = cursor + prefix_length + 1
        next_instruction = displacement_offset + 2
        target_cursor = (
            near_sink_offset
            if target_offset is None
            else target_offset - original_base
        )
        displacement = target_cursor - next_instruction
        image[displacement_offset : displacement_offset + 2] = (displacement & 0xFFFF).to_bytes(2, "little")
    for cursor, prefix_length, target_offset in unresolved_far_calls:
        pointer_offset = cursor + prefix_length + 1
        target_cursor = (
            far_sink_offset
            if target_offset is None
            else target_offset - original_base
        )
        image[pointer_offset : pointer_offset + 4] = _far_pointer_for_linear_addr_8616(
            image_base + target_cursor
        )
    return CODModuleAnalysisImage8616(
        code=bytes(image),
        original_base_offset=original_base,
        function_ranges=function_ranges,
        instruction_row_count=instruction_row_count,
    )


def _entry_offset_8616(entry: dict[str, object]) -> int | None:
    """Return one typed COD instruction offset."""
    offset = entry.get("offset")
    return offset if isinstance(offset, int) else None


def _entry_bytes_8616(entry: dict[str, object]) -> bytes | None:
    """Return one typed COD instruction byte string."""
    data = entry.get("bytes")
    return data if isinstance(data, bytes) else None


def _selected_entries_8616(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None,
    end_offset: int | None,
) -> tuple[dict[str, object], ...]:
    """Select the same ordered COD rows used by the byte-image joiner."""
    return tuple(
        entry
        for entry in entries
        if (offset := _entry_offset_8616(entry)) is not None
        and (start_offset is None or offset >= start_offset)
        and (end_offset is None or offset < end_offset)
        and _entry_bytes_8616(entry) is not None
    )


def _near_call_prefix_length_8616(data: bytes) -> int | None:
    """Return the prefix length when one instruction is a direct near call."""
    prefix_length = 0
    while prefix_length < len(data) and data[prefix_length] in _INSTRUCTION_PREFIXES:
        prefix_length += 1
    if prefix_length + 3 != len(data) or data[prefix_length] != 0xE8:
        return None
    return prefix_length


def _far_call_prefix_length_8616(data: bytes) -> int | None:
    """Return the prefix length when one instruction is a direct far call."""
    prefix_length = 0
    while prefix_length < len(data) and data[prefix_length] in _INSTRUCTION_PREFIXES:
        prefix_length += 1
    if prefix_length + 5 != len(data) or data[prefix_length] != 0x9A:
        return None
    return prefix_length


def _far_pointer_for_linear_addr_8616(linear_addr: int) -> bytes:
    """Encode one real-mode far pointer for a proven execution-linear address."""
    if not 0 <= linear_addr <= 0xFFFFF:
        raise ValueError(f"COD analysis-image far-call target is outside real-mode memory: {linear_addr:#x}")
    segment = linear_addr >> 4
    offset = linear_addr & 0xF
    return offset.to_bytes(2, "little") + segment.to_bytes(2, "little")


def _canonical_call_name_8616(raw_name: str) -> str:
    """Return a readable optional label for one exact COD call operand."""
    return canonical_known_cod_object_name(raw_name) or raw_name.lstrip("_")


def build_cod_analysis_image_8616(
    entries: list[dict[str, object]],
    *,
    start_offset: int | None = None,
    end_offset: int | None = None,
    image_base: int = 0x1000,
) -> CODAnalysisImage8616:
    """Build a COD image whose named direct calls cannot target fallthrough.

    Near stubs return with ``ret`` and far stubs with ``retf``. The explicit
    image base is required because immediate far pointers are absolute, unlike
    relative near-call displacements.
    """
    joined, synthetic_globals = join_cod_entries_with_synthetic_globals(
        entries,
        start_offset=start_offset,
        end_offset=end_offset,
    )
    selected_entries = _selected_entries_8616(
        entries,
        start_offset=start_offset,
        end_offset=end_offset,
    )
    calls: list[tuple[int, int, str, bool]] = []
    cursor = 0
    for entry in selected_entries:
        data = _entry_bytes_8616(entry)
        if data is None:
            continue
        prefix_length = _near_call_prefix_length_8616(data)
        call_match = _DIRECT_NEAR_CALL_RE.search(str(entry.get("text", "")))
        if prefix_length is not None and call_match is not None:
            calls.append((cursor, prefix_length, _canonical_call_name_8616(call_match.group("name")), False))
        far_prefix_length = _far_call_prefix_length_8616(data)
        far_call_match = _DIRECT_FAR_CALL_RE.search(str(entry.get("text", "")))
        if far_prefix_length is not None and far_call_match is not None:
            calls.append(
                (cursor, far_prefix_length, _canonical_call_name_8616(far_call_match.group("name")), True)
            )
        cursor += len(data)
    if cursor != len(joined):
        raise ValueError("COD analysis-image row lengths do not match joined bytes")

    call_keys = tuple(dict.fromkeys((name, is_far) for _cursor, _prefix_length, name, is_far in calls))
    stub_offsets = {key: len(joined) + index for index, key in enumerate(call_keys)}
    patched = bytearray(joined)
    for call_offset, prefix_length, name, is_far in calls:
        operand_offset = call_offset + prefix_length + 1
        stub_offset = stub_offsets[(name, is_far)]
        if is_far:
            patched[operand_offset : operand_offset + 4] = _far_pointer_for_linear_addr_8616(image_base + stub_offset)
        else:
            next_instruction = operand_offset + 2
            displacement = stub_offset - next_instruction
            patched[operand_offset : operand_offset + 2] = (displacement & 0xFFFF).to_bytes(2, "little")
    patched.extend(b"".join(b"\xcb" if is_far else b"\xc3" for _name, is_far in call_keys))
    return CODAnalysisImage8616(
        code=bytes(patched),
        synthetic_globals=synthetic_globals,
        call_target_offsets={offset: name for (name, _is_far), offset in stub_offsets.items()},
    )
