from __future__ import annotations

import re
import struct
from functools import lru_cache
from pathlib import Path

import angr
from angr_platforms.X86_16.cod_extract import CODListingMetadata, extract_cod_listing_metadata
from angr_platforms.X86_16.codeview_nb00 import parse_codeview_nb00
from angr_platforms.X86_16.codeview_nb02_nb04 import parse_codeview_nb0204_bytes
from angr_platforms.X86_16.flair_extract import list_flair_sig_libraries, match_flair_startup_entry
from angr_platforms.X86_16.ne_exe_parse import parse_ne_exe

from omf_pat import PatModule, discover_local_pat_matches, match_pat_modules, parse_pat_file
from signature_catalog import match_signature_catalog


_IDA_MAP_SEGMENT_RE = re.compile(
    r"^\s*([0-9A-Fa-f]+)H\s+[0-9A-Fa-f]+H\s+[0-9A-Fa-f]+H\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*$"
)
_IDA_MAP_PUBLIC_RE = re.compile(r"^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([A-Za-z_$?@][\w$?@]*)\s*$")
_IDA_LST_PROC_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+(?P<name>[A-Za-z_$?@][\w$?@]*)\s+proc\b",
    re.IGNORECASE,
)
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


def _label_looks_like_code(name: str) -> bool:
    return _label_looks_like_function(name)


def _label_looks_like_function(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(_NON_FUNCTION_CODE_PREFIXES):
        return False
    if "_" not in lowered:
        return True
    prefix, suffix = lowered.rsplit("_", 1)
    if suffix and all(ch in "0123456789abcdef" for ch in suffix):
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
                segment_offsets[segment_name] = start
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
        if segment_class == "CODE":
            code_labels.setdefault(linear, name.lstrip("_"))
        elif segment_class in {"DATA", "BSS", "STACK"}:
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
    """
    Parse CodeView NB02/NB04 debug information.
    
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
            linear_start = load_base_linear + (proc.segment << 4) + proc.offset if proc.segment is not None else load_base_linear + proc.offset
            if proc.length and proc.length > 0:
                linear_end = linear_start + proc.length
                if linear_start in code_labels:
                    code_ranges[linear_start] = (linear_start, linear_end)
    
    return code_labels, data_labels, code_ranges


def _parse_ne_exe_metadata(
    binary: Path,
    *,
    load_base_linear: int,
    project: angr.Project | None = None,
) -> tuple[dict[int, str], dict[int, str], dict[int, tuple[int, int]]]:
    """
    Parse NE (New Executable) format Windows/OS2 16-bit binaries.
    
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
) -> CODListingMetadata:
    metadata = extract_cod_listing_metadata(cod_path)
    existing = existing_code_labels or {}
    delta_candidates: dict[int, int] = {}
    normalized_existing = {name.lstrip("_"): addr for addr, name in existing.items()}
    for offset, name in metadata.code_labels.items():
        existing_addr = normalized_existing.get(name.lstrip("_"))
        if existing_addr is None:
            continue
        delta = existing_addr - offset
        delta_candidates[delta] = delta_candidates.get(delta, 0) + 1
    cod_linear_base = sorted(delta_candidates.items(), key=lambda item: (-item[1], item[0]))[0][0] if delta_candidates else load_base_linear
    code_labels = {cod_linear_base + offset: name.lstrip("_") for offset, name in metadata.code_labels.items()}
    code_ranges = {
        cod_linear_base + offset: (cod_linear_base + span[0], cod_linear_base + span[1])
        for offset, span in metadata.code_ranges.items()
    }
    proc_kinds = {cod_linear_base + offset: kind for offset, kind in metadata.proc_kinds.items()}
    return CODListingMetadata(code_labels=code_labels, code_ranges=code_ranges, proc_kinds=proc_kinds)


def _ranges_overlap_or_touch(left: tuple[int, int] | None, right: tuple[int, int] | None, *, slop: int = 0x20) -> bool:
    if left is None or right is None:
        return False
    return max(left[0], right[0]) <= min(left[1], right[1]) + slop


def _reconcile_cod_listing_with_codeview(
    cod_listing: CODListingMetadata,
    codeview_code: dict[int, str],
    codeview_ranges: dict[int, tuple[int, int]],
) -> CODListingMetadata:
    if not cod_listing.code_labels or not codeview_code:
        return cod_listing
    codeview_by_name: dict[str, list[tuple[int, tuple[int, int] | None]]] = {}
    for addr, name in codeview_code.items():
        codeview_by_name.setdefault(name.lstrip("_"), []).append((addr, codeview_ranges.get(addr)))
    filtered_labels: dict[int, str] = {}
    filtered_ranges: dict[int, tuple[int, int]] = {}
    filtered_proc_kinds: dict[int, str] = {}
    for addr, name in cod_listing.code_labels.items():
        normalized_name = name.lstrip("_")
        cod_range = cod_listing.code_ranges.get(addr)
        matched_codeview_addr: int | None = None
        for codeview_addr, codeview_range in codeview_by_name.get(normalized_name, ()):
            if abs(codeview_addr - addr) <= 0x400 or _ranges_overlap_or_touch(cod_range, codeview_range):
                matched_codeview_addr = codeview_addr
                break
        proc_kind = cod_listing.proc_kinds.get(addr)
        if matched_codeview_addr is not None:
            if proc_kind is not None:
                filtered_proc_kinds.setdefault(matched_codeview_addr, proc_kind)
            continue
        filtered_labels[addr] = name
        if cod_range is not None:
            filtered_ranges[addr] = cod_range
        if proc_kind is not None:
            filtered_proc_kinds[addr] = proc_kind
    return CODListingMetadata(code_labels=filtered_labels, code_ranges=filtered_ranges, proc_kinds=filtered_proc_kinds)


def _detect_flair_metadata(
    binary: Path,
    project: angr.Project,
    *,
    pat_backend: str | None = None,
    signature_catalog: Path | None = None,
) -> tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]]:
    flair_root = Path("/home/xor/ida77/flair77")
    if not flair_root.exists():
        return {}, {}, ()
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return {}, {}, ()
    try:
        entry_bytes = bytes(project.loader.memory.load(project.entry, 32))
    except Exception:
        entry_bytes = b""
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    source_parts: list[str] = []
    startup_matches = match_flair_startup_entry(entry_bytes, flair_root)
    startup_pat_labels, startup_pat_ranges = _match_flair_startup_pat_functions(
        project,
        flair_root,
        backend=pat_backend,
    )
    if startup_pat_labels or startup_pat_ranges:
        source_parts.append("flair_pat")
        for addr, name in startup_pat_labels.items():
            code_labels.setdefault(addr, name)
        for addr, span in startup_pat_ranges.items():
            code_ranges.setdefault(addr, span)
    elif startup_matches:
        source_parts.append("flair_pat")
        first = startup_matches[0]
        for offset, name in first.public_names:
            linear = project.entry + offset
            code_labels.setdefault(linear, name.lstrip("_"))
        if first.public_names:
            first_offset = min(offset for offset, _name in first.public_names)
            start = project.entry + first_offset
            code_ranges.setdefault(start, (start, start + 0x100))
    sig_libraries = [
        library
        for library in list_flair_sig_libraries(flair_root)
        if "MSDOS" in library.os_types.upper() and "16BIT" in library.app_types.upper()
    ]
    if sig_libraries:
        source_parts.append("flair_sig")
        setattr(project, "_inertia_flair_sig_titles", tuple(library.title for library in sig_libraries[:8]))
    if startup_matches:
        setattr(project, "_inertia_flair_startup_matches", tuple(match.pat_path for match in startup_matches))
    if signature_catalog is not None:
        catalog_matches = match_signature_catalog(signature_catalog, binary, project, backend=pat_backend)
        if catalog_matches.code_labels or catalog_matches.code_ranges:
            for addr, name in catalog_matches.code_labels.items():
                code_labels.setdefault(addr, name)
            for addr, span in catalog_matches.code_ranges.items():
                code_ranges.setdefault(addr, span)
            source_parts.extend(catalog_matches.source_formats)
    local_pat_matches = discover_local_pat_matches(binary, project, flair_root=flair_root, backend=pat_backend)
    if local_pat_matches.code_labels or local_pat_matches.code_ranges:
        for addr, name in local_pat_matches.code_labels.items():
            code_labels.setdefault(addr, name)
        for addr, span in local_pat_matches.code_ranges.items():
            code_ranges.setdefault(addr, span)
        source_parts.extend(local_pat_matches.source_formats)
        setattr(project, "_inertia_flair_local_pat_sources", tuple(dict.fromkeys(local_pat_matches.source_formats)))
    return code_labels, code_ranges, tuple(source_parts)


@lru_cache(maxsize=1)
def _load_flair_startup_pat_modules(flair_root: str) -> tuple[PatModule, ...]:
    root = Path(flair_root)
    modules: list[PatModule] = []
    for pat_path in sorted((root / "startup").rglob("*.pat")):
        try:
            modules.extend(parse_pat_file(pat_path))
        except OSError:
            continue
    return tuple(modules)


def _match_flair_startup_pat_functions(
    project: angr.Project,
    flair_root: Path,
    *,
    backend: str | None = None,
) -> tuple[dict[int, str], dict[int, tuple[int, int]]]:
    main_object = getattr(project.loader, "main_object", None)
    memory = getattr(project.loader, "memory", None)
    if main_object is None or memory is None:
        return {}, {}
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return {}, {}
    try:
        image_bytes = bytes(memory.load(min_addr, max_addr - min_addr + 1))
    except Exception:
        return {}, {}
    modules = _load_flair_startup_pat_modules(str(flair_root))
    if not modules:
        return {}, {}
    return match_pat_modules(image_bytes, min_addr, modules, backend=backend)


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
