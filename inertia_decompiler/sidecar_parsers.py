"""Parse sidecar formats into structured optional evidence records.

Layer: CLI/fallback/reporting.
Responsibility: translate optional sidecar/debug formats into structured evidence records.
Dynamic angr boundary: sidecar probing reads loader/project/memory attributes supplied by angr backends.
"""

from __future__ import annotations

import re
import struct
import tempfile
import typing
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path
from typing import Protocol, cast

import angr
from angr_platforms.X86_16.cod_extract import (
    CODListingMetadata,
    extract_cod_function_entries,
    extract_cod_listing_metadata,
)
from angr_platforms.X86_16.codeview_nb00 import parse_codeview_nb00
from angr_platforms.X86_16.codeview_nb02_nb04 import parse_codeview_nb0204_bytes
from angr_platforms.X86_16.flair_extract import FlairStartupPattern, match_flair_startup_entry
from angr_platforms.X86_16.ne_exe_parse import parse_ne_exe

from inertia_decompiler.flair_paths import flair_signature_root
from omf_pat import (
    CachedPatRegexSpec,
    load_cached_pat_regex_specs,
    match_pat_modules,
)
from signature_catalog import match_signature_catalog


class _AngrMemoryLoader8616(Protocol):
    """Dynamic angr loader-memory surface used for sidecar byte probes."""

    def load(self, addr: int, size: int) -> bytes | bytearray | memoryview:
        """Return bytes from an angr loader memory object."""
        ...


_IDA_MAP_SEGMENT_RE = re.compile(
    r"^\s*([0-9A-Fa-f]+)H\s+[0-9A-Fa-f]+H\s+[0-9A-Fa-f]+H\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*$"
)
_IDA_MAP_PUBLIC_RE = re.compile(r"^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([A-Za-z_$?@][\w$?@]*)\s*$")
_IDA_LST_PROC_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\s+proc\b",
    re.IGNORECASE,
)
_IDA_LST_ENDP_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\s+endp\b",
    re.IGNORECASE,
)
_IDA_LST_ADDR_RE = re.compile(r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\b")
_IDC_SET_NAME_RE = re.compile(r"set_name\s*\(\s*0X([0-9A-Fa-f]+)\s*,\s*\"([^\"]+)\"", re.IGNORECASE)
_INC_STRUCT_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s+struc\b")
_MZRE_SEGMENT_RE = re.compile(r"^([A-Za-z_]\w*)\s+(CODE|DATA|STACK)\s+([0-9A-Fa-f]+)$", re.IGNORECASE)
_MZRE_ROUTINE_RE = re.compile(
    r"^([A-Za-z_]\w*):\s+([A-Za-z_]\w*)\s+(?:NEAR|FAR)\s+([0-9A-Fa-f]+)-([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_NON_FUNCTION_CODE_PREFIXES = (
    "loc_",
    "locret_",
    "byte_",
    "word_",
    "dword_",
    "off_",
    "stru_",
    "align_",
    "cond_",
    "else_",
    "loop_",
    "next_",
    "break_",
    "continue_",
    "endif_",
)
_CONTROL_FLOW_LABEL_TOKENS = ("cond", "else", "loop", "next", "break", "continue", "endif", "out", "inner", "openok")
_IDA_MAP_CODE_CLASSES = {"CODE", "ENDCODE"}
_IDA_MAP_DATA_CLASSES = {
    "BEGDATA",
    "BSS",
    "CONST",
    "DATA",
    "ENDDATA",
    "FAR_DATA",
    "MSG",
    "STACK",
}


def _label_looks_like_code(name: str) -> bool:
    return _label_looks_like_function(name)


def _label_looks_like_function(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(_NON_FUNCTION_CODE_PREFIXES):
        return False
    if "_" not in lowered:
        return True
    prefix, suffix = lowered.rsplit("_", 1)
    if suffix and all(ch in "0123456789abcdef" for ch in suffix):  # noqa: SIM102
        if any(token in prefix for token in _CONTROL_FLOW_LABEL_TOKENS):
            return False
    return True


def _parse_ida_map_metadata(
    map_path: Path,
    *,
    load_base_linear: int,
) -> tuple[dict[int, str], dict[int, str], dict[str, int]]:
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    segment_offsets: dict[str, int] = {}
    segment_classes: dict[int, str] = {}
    in_publics = False
    for line in map_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "Publics by Value" in stripped:
            in_publics = True
            continue
        if not in_publics:
            match = _IDA_MAP_SEGMENT_RE.match(stripped)
            if match is not None:
                start = int(match.group(1), 16)
                segment_name = match.group(2)
                segment_class = match.group(3).upper()
                # IDA's MAP segment start includes any leading ``org`` bytes,
                # while LST ``segment:offset`` addresses already include that
                # offset.  Retain the paragraph base or the leading bytes are
                # counted twice (for example 03F93 + 0003 instead of
                # 03F90 + 0003).
                segment_offsets[segment_name] = start & ~0xF
                segment_classes[start >> 4] = segment_class
            continue
        match = _IDA_MAP_PUBLIC_RE.match(stripped)
        if match is None:
            continue
        segment = int(match.group(1), 16)
        offset = int(match.group(2), 16)
        name = match.group(3)
        linear = load_base_linear + (segment << 4) + offset
        segment_class = segment_classes.get(segment)
        if segment_class in _IDA_MAP_CODE_CLASSES:
            code_labels.setdefault(linear, name.lstrip("_"))
        elif segment_class in _IDA_MAP_DATA_CLASSES:
            data_labels.setdefault(linear, name)
        elif _label_looks_like_code(name):
            code_labels.setdefault(linear, name.lstrip("_"))
        else:
            data_labels.setdefault(linear, name)
    return code_labels, data_labels, segment_offsets


def _parse_ida_lst_proc_metadata(
    lst_path: Path,
    *,
    load_base_linear: int,
    segment_offsets: dict[str, int],
) -> dict[int, str]:
    code_labels: dict[int, str] = {}
    for line in lst_path.read_text(errors="ignore").splitlines():
        match = _IDA_LST_PROC_RE.match(line.strip())
        if match is None:
            continue
        segment_name = match.group("seg")
        if segment_name not in segment_offsets:
            continue
        offset = int(match.group("off"), 16)
        linear = load_base_linear + segment_offsets[segment_name] + offset
        code_labels.setdefault(linear, match.group("name").lstrip("_"))
    return code_labels


def _parse_ida_lst_proc_ranges(
    lst_path: Path,
    *,
    load_base_linear: int,
    segment_offsets: dict[str, int],
) -> dict[int, tuple[int, int]]:
    """Return exact IDA ``proc``/``endp`` ranges in linear address space."""
    lines = lst_path.read_text(errors="ignore").splitlines()
    offsets_by_segment: dict[str, set[int]] = {}
    for line in lines:
        match = _IDA_LST_ADDR_RE.match(line.strip())
        if match is not None:
            offsets_by_segment.setdefault(match.group("seg"), set()).add(int(match.group("off"), 16))
    ordered_offsets = {segment: sorted(offsets) for segment, offsets in offsets_by_segment.items()}

    starts: dict[tuple[str, str], int] = {}
    ranges: dict[int, tuple[int, int]] = {}
    for line in lines:
        stripped = line.strip()
        proc_match = _IDA_LST_PROC_RE.match(stripped)
        if proc_match is not None:
            starts[(proc_match.group("seg"), proc_match.group("name").lstrip("_"))] = int(
                proc_match.group("off"), 16
            )
            continue
        endp_match = _IDA_LST_ENDP_RE.match(stripped)
        if endp_match is None:
            continue
        segment = endp_match.group("seg")
        if segment not in segment_offsets:
            continue
        key = (segment, endp_match.group("name").lstrip("_"))
        start_offset = starts.pop(key, None)
        if start_offset is None:
            continue
        endp_offset = int(endp_match.group("off"), 16)
        offsets = ordered_offsets.get(segment, ())
        next_index = bisect_right(offsets, endp_offset)
        end_offset = offsets[next_index] if next_index < len(offsets) else endp_offset + 1
        segment_base = load_base_linear + segment_offsets[segment]
        start = segment_base + start_offset
        ranges[start] = (start, segment_base + end_offset)
    return ranges


def _parse_idc_metadata(idc_path: Path) -> tuple[dict[int, str], dict[int, str]]:
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    for line in idc_path.read_text(errors="ignore").splitlines():
        match = _IDC_SET_NAME_RE.search(line)
        if match is None:
            continue
        addr = int(match.group(1), 16)
        name = match.group(2)
        if _label_looks_like_function(name):
            code_labels.setdefault(addr, name.lstrip("_"))
        else:
            data_labels.setdefault(addr, name)
    return code_labels, data_labels


def _parse_inc_struct_names(inc_path: Path) -> tuple[str, ...]:
    names: list[str] = []
    for line in inc_path.read_text(errors="ignore").splitlines():
        match = _INC_STRUCT_RE.match(line)
        if match is not None:
            names.append(match.group(1))
    return tuple(names)


def _parse_codeview_nb00_metadata(
    binary: Path,
    *,
    load_base_linear: int,
) -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
    parsed = parse_codeview_nb00(binary, load_base_linear=load_base_linear)
    if parsed is None:
        return {}, {}, {}
    code_labels = {addr: name for addr, name in parsed.code_labels.items() if _label_looks_like_code(name)}
    data_labels = {addr: name for addr, name in parsed.data_labels.items() if addr not in code_labels}
    code_ranges = {addr: span for addr, span in parsed.code_ranges.items() if addr in code_labels and span[0] < span[1]}
    return code_labels, data_labels, code_ranges


def _parse_codeview_nb0204_metadata(
    binary: Path,
    *,
    load_base_linear: int,
) -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
    def _impl() -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
        """Parse CodeView NB02/NB04 debug information.

        Extracts:
        - Function names (from S_GPROC16, SST_PUBLIC)
        - Global/local data (from S_GDATA16, S_LDATA16)
        - Stack variables (from S_BPREL16, available via procedures dict)
        """
        try:
            data = binary.read_bytes()
            parsed = parse_codeview_nb0204_bytes(data, load_base_linear=load_base_linear)
        except (OSError, ValueError):
            parsed = None

        if parsed is None:
            return {}, {}, {}

        code_labels = {addr: name for addr, name in parsed.code_labels.items() if _label_looks_like_code(name)}
        data_labels = {addr: name for addr, name in parsed.data_labels.items() if addr not in code_labels}

        # Synthesize code ranges from procedures if available
        code_ranges: dict[int, tuple[int, int]] = {}
        for proc in parsed.procedures:
            if proc.is_procedure() and proc.name:
                linear_start = (
                    load_base_linear + (proc.segment << 4) + proc.offset
                    if proc.segment is not None
                    else load_base_linear + proc.offset
                )
                if proc.length and proc.length > 0:
                    linear_end = linear_start + proc.length
                    if linear_start in code_labels:
                        code_ranges[linear_start] = (linear_start, linear_end)

        return code_labels, data_labels, code_ranges

    return _impl()


def _parse_ne_exe_metadata(
    binary: Path,
    *,
    load_base_linear: int,
    project: angr.Project | None = None,
) -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
    """Parse NE (New Executable) format Windows/OS2 16-bit binaries.

    Integrates with CLE DOSNE loader for accurate segment-to-linear address mapping.

    Extracts:
    - Function names from resident names table
    - Entry point addresses from entry table + segment table
    - Uses loader's segment mappings if project available
    """
    try:
        ne_info = parse_ne_exe(binary, load_base_linear=load_base_linear, project=project)
    except (OSError, ValueError, struct.error):
        ne_info = None

    if ne_info is None or not ne_info.code_labels:
        return {}, {}, {}

    code_labels = {addr: name for addr, name in ne_info.code_labels.items() if _label_looks_like_code(name)}
    data_labels = {addr: name for addr, name in ne_info.data_labels.items() if addr not in code_labels}

    # NE format doesn't provide code range info directly, would need debug tables
    code_ranges: dict[int, tuple[int, int]] = {}

    return code_labels, data_labels, code_ranges


def _parse_cod_sidecar_metadata(
    cod_path: Path,
    *,
    load_base_linear: int,
    existing_code_labels: dict[int, str] | None = None,
    project: angr.Project | None = None,
) -> CODListingMetadata:
    def _impl() -> CODListingMetadata:
        metadata = extract_cod_listing_metadata(cod_path)
        existing = existing_code_labels or {}
        base_candidates: dict[int, int] = {}
        delta_candidates: dict[int, int] = {}
        normalized_existing = {name.lstrip("_"): addr for addr, name in existing.items()}

        _accumulate_base_candidates_8616(metadata, normalized_existing, base_candidates)
        if project is not None:
            # Dynamic angr boundary: project loader memory is supplied by angr backends.
            memory = getattr(getattr(project, "loader", None), "memory", None)
            if memory is not None:
                _scan_cod_base_deltas_8616(metadata, cod_path, load_base_linear, memory, delta_candidates)
        cod_linear_base = load_base_linear
        if base_candidates:
            cod_linear_base = sorted(base_candidates.items(), key=lambda item: (-item[1], item[0]))[0][0]
        if delta_candidates:
            cod_linear_base = (
                load_base_linear
                + sorted(delta_candidates.items(), key=lambda item: (-item[1], abs(item[0]), item[0]))[0][0]
            )
        code_labels = {cod_linear_base + offset: name.lstrip("_") for offset, name in metadata.code_labels.items()}
        code_ranges = {
            cod_linear_base + offset: (cod_linear_base + span[0], cod_linear_base + span[1])
            for offset, span in metadata.code_ranges.items()
        }
        proc_kinds = {cod_linear_base + offset: kind for offset, kind in metadata.proc_kinds.items()}
        return CODListingMetadata(code_labels=code_labels, code_ranges=code_ranges, proc_kinds=proc_kinds)

    return _impl()


def _cod_entry_pattern_8616(entries: list[dict[str, object]]) -> tuple[int | None, ...]:
    pattern: list[int | None] = []
    concrete = 0
    for entry in entries:
        entry_bytes = entry.get("bytes")
        if not isinstance(entry_bytes, (bytes, bytearray)) or not entry_bytes:
            continue
        first = int(entry_bytes[0])
        if first in {0xE8, 0xE9} and len(entry_bytes) >= 3:
            pattern.extend((first, None, None))
            concrete += 1
        elif first == 0x9A and len(entry_bytes) >= 5:
            pattern.extend((first, None, None, None, None))
            concrete += 1
        else:
            pattern.extend(int(byte) for byte in entry_bytes)
            concrete += len(entry_bytes)
        if len(pattern) >= 24 and concrete >= 12:
            break
    return tuple(pattern) if len(pattern) >= 12 and concrete >= 8 else ()


def _memory_matches_cod_pattern_8616(
    memory_obj: object, candidate: int, pattern: tuple[int | None, ...]
) -> bool:
    try:
        observed = bytes(cast(_AngrMemoryLoader8616, memory_obj).load(candidate, len(pattern)))
    except Exception:
        return False
    return all(expected is None or observed[idx] == expected for idx, expected in enumerate(pattern))


def _accumulate_base_candidates_8616(
    metadata: CODListingMetadata,
    normalized_existing: dict[str, int],
    base_candidates: dict[int, int],
) -> None:
    for offset, name in metadata.code_labels.items():
        existing_addr = normalized_existing.get(name.lstrip("_"))
        if existing_addr is None:
            continue
        base = existing_addr - offset
        base_candidates[base] = base_candidates.get(base, 0) + 1


def _scan_cod_base_deltas_8616(
    metadata: CODListingMetadata,
    cod_path: Path,
    load_base_linear: int,
    memory: object,
    delta_candidates: dict[int, int],
) -> None:
    for offset, name in metadata.code_labels.items():
        proc_kind = metadata.proc_kinds.get(offset, "NEAR")
        try:
            entries = extract_cod_function_entries(cod_path, name, proc_kind)
        except Exception:
            continue
        pattern = _cod_entry_pattern_8616(entries)
        if not pattern:
            continue
        expected = load_base_linear + offset
        for delta in range(-0x20, 0x21):
            candidate = expected + delta
            if _memory_matches_cod_pattern_8616(memory, candidate, pattern):
                delta_candidates[delta] = delta_candidates.get(delta, 0) + 1
                break


def _ranges_overlap_or_touch(left: tuple[int, int] | None, right: tuple[int, int] | None, *, slop: int = 0x20) -> bool:
    if left is None or right is None:
        return False
    return max(left[0], right[0]) <= min(left[1], right[1]) + slop


def _reconcile_cod_listing_with_codeview(
    cod_listing: CODListingMetadata,
    codeview_code: dict[int, str],
    codeview_ranges: dict[int, tuple[int, int]],
) -> CODListingMetadata:
    """Re-key matching COD evidence to the authoritative CodeView entry."""

    def _impl() -> CODListingMetadata:
        if not cod_listing.code_labels or not codeview_code:
            return cod_listing
        codeview_by_name: dict[str, list[tuple[int, tuple[int, int] | None]]] = {}
        for addr, name in codeview_code.items():
            codeview_by_name.setdefault(name.lstrip("_"), []).append((addr, codeview_ranges.get(addr)))
        filtered_labels: dict[int, str] = {}
        filtered_ranges: dict[int, tuple[int, int]] = {}
        filtered_proc_kinds: dict[int, str] = {}
        for addr, name in cod_listing.code_labels.items():
            _reconcile_cod_label_8616(
                addr,
                name,
                cod_listing,
                codeview_by_name,
                filtered_labels,
                filtered_ranges,
                filtered_proc_kinds,
            )
        return CODListingMetadata(
            code_labels=filtered_labels, code_ranges=filtered_ranges, proc_kinds=filtered_proc_kinds
        )

    return _impl()


def _reconcile_cod_label_8616(
    addr: int,
    name: str,
    cod_listing: CODListingMetadata,
    codeview_by_name: dict[str, list[tuple[int, tuple[int, int] | None]]],
    filtered_labels: dict[int, str],
    filtered_ranges: dict[int, tuple[int, int]],
    filtered_proc_kinds: dict[int, str],
) -> None:
    normalized_name = name.lstrip("_")
    cod_range = cod_listing.code_ranges.get(addr)
    matched_codeview_addr: int | None = None
    for codeview_addr, codeview_range in codeview_by_name.get(normalized_name, ()):
        if abs(codeview_addr - addr) <= 0x400 or _ranges_overlap_or_touch(cod_range, codeview_range):
            matched_codeview_addr = codeview_addr
            break
    proc_kind = cod_listing.proc_kinds.get(addr)
    if matched_codeview_addr is not None:
        filtered_labels.setdefault(matched_codeview_addr, name)
        if cod_range is not None:
            filtered_ranges.setdefault(matched_codeview_addr, cod_range)
        if proc_kind is not None:
            filtered_proc_kinds.setdefault(matched_codeview_addr, proc_kind)
        return
    filtered_labels[addr] = name
    if cod_range is not None:
        filtered_ranges[addr] = cod_range
    if proc_kind is not None:
        filtered_proc_kinds[addr] = proc_kind


def _detect_flair_metadata(
    binary: Path,
    project: angr.Project,
    *,
    pat_backend: str | None = None,
    signature_catalog: Path | None = None,
) -> tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]]:
    """Merge independent optional startup patterns and binary catalog matches."""
    def _impl() -> tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]]:
        flair_root = flair_signature_root()
        # Startup matchers tolerate missing assets; an explicit catalog is independent.
        # Dynamic angr boundary: loader objects expose backend-specific main object metadata.
        main_object = getattr(project.loader, "main_object", None)
        if main_object is None:
            return {}, {}, ()
        try:
            entry_bytes = bytes(project.loader.memory.load(project.entry, 32))
        except Exception:
            entry_bytes = b""
        code_labels: dict[int, str] = {}
        code_ranges: dict[int, tuple[int, int]] = {}
        matched_compiler_names: list[str] = []
        source_parts: list[str] = []

        startup_matches = match_flair_startup_entry(entry_bytes, flair_root)
        startup_pat_result = _match_flair_startup_pat_functions(
            project,
            flair_root,
            backend=pat_backend,
        )
        _merge_startup_flair_evidence_8616(
            project,
            startup_matches,
            startup_pat_result,
            code_labels,
            code_ranges,
            matched_compiler_names,
            source_parts,
        )
        if signature_catalog is not None:
            _merge_signature_catalog_8616(
                signature_catalog,
                binary,
                project,
                pat_backend,
                matched_compiler_names,
                code_labels,
                code_ranges,
                source_parts,
            )
        if matched_compiler_names:
            # Dynamic angr boundary: project metadata is attached to the live angr project.
            typing.cast(typing.Any, project)._inertia_signature_compiler_names = tuple(matched_compiler_names)
        return code_labels, code_ranges, tuple(source_parts)

    return _impl()


def _remember_compiler_8616(matched_compiler_names: list[str], name: str | None) -> None:
    if not name:
        return
    normalized = name.strip()
    if normalized and normalized not in matched_compiler_names:
        matched_compiler_names.append(normalized)


def _merge_startup_flair_evidence_8616(
    project: angr.Project,
    startup_matches: tuple[FlairStartupPattern, ...],
    startup_pat_result: tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]],
    code_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    matched_compiler_names: list[str],
    source_parts: list[str],
) -> None:
    startup_pat_labels, startup_pat_ranges, startup_pat_compiler_names = startup_pat_result
    if startup_pat_labels or startup_pat_ranges:
        source_parts.append("startup_flair_pat")
        for compiler_name in startup_pat_compiler_names:
            _remember_compiler_8616(matched_compiler_names, compiler_name)
        for addr, name in startup_pat_labels.items():
            code_labels.setdefault(addr, name)
        for addr, span in startup_pat_ranges.items():
            code_ranges.setdefault(addr, span)
    elif startup_matches:
        source_parts.append("startup_flair_pat")
        first = startup_matches[0]
        _remember_compiler_8616(matched_compiler_names, first.compiler_tag)
        for offset, name in first.public_names:
            linear = project.entry + offset
            code_labels.setdefault(linear, name.lstrip("_"))
        if first.public_names:
            first_offset = min(offset for offset, _name in first.public_names)
            start = project.entry + first_offset
            code_ranges.setdefault(start, (start, start + 0x100))
    if startup_matches:
        # Dynamic angr boundary: project metadata is attached to the live angr project.
        typing.cast(typing.Any, project)._inertia_flair_startup_matches = tuple(match.pat_path for match in startup_matches)
        for match in startup_matches:
            _remember_compiler_8616(matched_compiler_names, match.compiler_tag)


def _merge_signature_catalog_8616(
    signature_catalog: Path,
    binary: Path,
    project: angr.Project,
    pat_backend: str | None,
    matched_compiler_names: list[str],
    code_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    source_parts: list[str],
) -> None:
    catalog_matches = match_signature_catalog(
        signature_catalog,
        binary,
        project,
        backend=pat_backend,
        compiler_names=tuple(matched_compiler_names),
    )
    if catalog_matches.code_labels or catalog_matches.code_ranges:
        for addr, name in catalog_matches.code_labels.items():
            code_labels.setdefault(addr, name)
        for addr, span in catalog_matches.code_ranges.items():
            code_ranges.setdefault(addr, span)
        source_parts.extend(catalog_matches.source_formats)
    # Dynamic compatibility boundary: catalog match objects may come from older helpers.
    for compiler_name in getattr(catalog_matches, "matched_compiler_names", ()):
        _remember_compiler_8616(matched_compiler_names, compiler_name)


@lru_cache(maxsize=1)
def _load_flair_startup_pat_modules(flair_root: str) -> tuple[CachedPatRegexSpec, ...]:
    root = Path(flair_root)
    cache_dir = _startup_pat_cache_dir(root / "startup")
    modules: list[CachedPatRegexSpec] = []
    for pat_path in sorted((root / "startup").rglob("*.pat")):
        try:
            modules.extend(load_cached_pat_regex_specs(pat_path, cache_dir))
        except OSError:
            continue
    return tuple(modules)


def _startup_pat_cache_dir(pat_root: Path) -> Path:
    preferred = pat_root / ".inertia_pat_cache"
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_test"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        return preferred
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "inertia_pat_cache"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _match_flair_startup_pat_functions(
    project: angr.Project,
    flair_root: Path,
    *,
    backend: str | None = None,
) -> tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]]:
    # Dynamic angr boundary: loader objects expose backend-specific main object metadata.
    main_object = getattr(project.loader, "main_object", None)
    # Dynamic angr boundary: project loader memory is supplied by angr backends.
    memory = getattr(project.loader, "memory", None)
    if main_object is None or memory is None:
        return {}, {}, ()
    # Dynamic angr boundary: backend main objects expose image address bounds.
    min_addr = getattr(main_object, "min_addr", None)
    # Dynamic angr boundary: backend main objects expose image address bounds.
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return {}, {}, ()
    try:
        image_bytes = bytes(memory.load(min_addr, max_addr - min_addr + 1))
    except Exception:
        return {}, {}, ()
    modules = _load_flair_startup_pat_modules(str(flair_root))
    if not modules:
        return {}, {}, ()
    pat_result = match_pat_modules(
        image_bytes,
        min_addr,
        modules,
        backend=backend,
    )
    code_labels, code_ranges, matched_compiler_names = pat_result
    return code_labels, code_ranges, matched_compiler_names


def _parse_mzre_map_metadata(
    map_path: Path,
    *,
    load_base_linear: int,
) -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    segment_paragraphs: dict[str, int] = {}
    for line in map_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        segment_match = _MZRE_SEGMENT_RE.match(stripped)
        if segment_match is not None:
            segment_paragraphs[segment_match.group(1)] = int(segment_match.group(3), 16)
            continue
        routine_match = _MZRE_ROUTINE_RE.match(stripped)
        if routine_match is not None:
            segment_name = routine_match.group(2)
            if segment_name not in segment_paragraphs:
                continue
            start = int(routine_match.group(3), 16)
            end = int(routine_match.group(4), 16)
            linear = load_base_linear + (segment_paragraphs[segment_name] << 4) + start
            linear_end = load_base_linear + (segment_paragraphs[segment_name] << 4) + end + 1
            code_labels.setdefault(linear, routine_match.group(1).lstrip("_"))
            code_ranges.setdefault(linear, (linear, linear_end))
    return code_labels, data_labels, code_ranges


def _synthesize_code_ranges(
    code_labels: dict[int, str],
    existing_ranges: dict[int, tuple[int, int]],
    *,
    image_end: int | None,
) -> dict[int, tuple[int, int]]:
    synthesized = dict(existing_ranges)
    ordered = sorted(code_labels)
    for index, start in enumerate(ordered):
        if start in synthesized:
            continue
        next_start = ordered[index + 1] if index + 1 < len(ordered) else image_end
        if next_start is None or next_start <= start:
            continue
        synthesized[start] = (start, next_start)
    return synthesized
