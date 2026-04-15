from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import hashlib
import pickle
import re
import subprocess
import tempfile

from inertia_decompiler.signature_matching_policy import signature_matching_disabled

try:
    import hyperscan as _hyperscan
except Exception:
    _hyperscan = None


@dataclass(frozen=True)
class PatPublicName:
    offset: int
    name: str


@dataclass(frozen=True)
class PatModule:
    source_path: str
    compiler_name: str
    module_name: str
    pattern_bytes: tuple[int | None, ...]
    module_length: int
    public_names: tuple[PatPublicName, ...]
    referenced_names: tuple[PatPublicName, ...]
    tail_bytes: tuple[int | None, ...]


@dataclass(frozen=True)
class LocalPatMatchResult:
    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]]
    source_formats: tuple[str, ...]
    matched_compiler_names: tuple[str, ...] = ()


@dataclass
class _OMFSegment:
    name: str
    class_name: str
    declared_length: int
    data: bytearray
    max_written_end: int = 0


@dataclass(frozen=True)
class _OMFPublic:
    seg_index: int
    offset: int
    name: str


@dataclass(frozen=True)
class _OMFFixupRef:
    seg_index: int
    offset: int
    width: int
    name: str


@dataclass(frozen=True)
class _OMFDataRecordContext:
    seg_index: int
    data_offset: int
    data_length: int


@dataclass(frozen=True)
class OMFModuleBlob:
    module_name: str
    data: bytes
    page_offset: int
    page_number: int
    dependency_indexes: tuple[int, ...] = ()


@dataclass(frozen=True)
class MicrosoftLibHeader:
    page_size: int
    dictionary_offset: int
    dictionary_blocks: int
    case_sensitive: bool


@dataclass(frozen=True)
class MicrosoftLibExtendedRecord:
    page_number: int
    dependency_offset: int
    dependency_indexes: tuple[int, ...]


@dataclass(frozen=True)
class MicrosoftLibDictionaryEntry:
    symbol_name: str
    module_page: int
    page_index: int
    bucket_index: int


@dataclass(frozen=True)
class MicrosoftLibMetadata:
    header: MicrosoftLibHeader
    modules: tuple[OMFModuleBlob, ...]
    dictionary_entries: tuple[MicrosoftLibDictionaryEntry, ...]
    extended_records: tuple[MicrosoftLibExtendedRecord, ...]


@dataclass(frozen=True)
class CachedPatRegexSpec:
    source_path: str
    compiler_name: str
    module_name: str
    regex_source: bytes
    scan_source: bytes
    checked_match_length: int
    module_length: int
    public_names: tuple[PatPublicName, ...]
    referenced_names: tuple[PatPublicName, ...]


_PAT_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}|\.\.)+$")
_PAT_PUBLIC_RE = re.compile(r"^:(?P<offset>-?[0-9A-Fa-f]{4,8})(?:@)?$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_PAT_MERGE_NAME_RE = re.compile(r"^_*([A-Za-z0-9](?:[A-Za-z0-9_]*[A-Za-z0-9])?)_*$")


def parse_pat_file(pat_path: Path) -> tuple[PatModule, ...]:
    if signature_matching_disabled():
        return ()
    modules: list[PatModule] = []
    try:
        lines = pat_path.read_text(errors="ignore").splitlines()
    except OSError:
        return ()
    for line in lines:
        parsed = parse_pat_line(line, source_path=str(pat_path))
        if parsed is not None:
            modules.append(parsed)
    return tuple(modules)


def parse_pat_line(line: str, *, source_path: str = "<memory>") -> PatModule | None:
    stripped = line.strip()
    if not stripped or stripped == "---":
        return None
    comment_text = ""
    if ";" in stripped:
        stripped, comment_text = stripped.split(";", 1)
        stripped = stripped.rstrip()
        comment_text = comment_text.strip()
    parts = stripped.split()
    if len(parts) < 5:
        return None
    pattern_text = parts[0]
    if len(pattern_text) < 64 or not _PAT_HEX_RE.fullmatch(pattern_text):
        return None
    try:
        module_length = int(parts[3], 16)
    except ValueError:
        return None
    pattern_bytes = tuple(_decode_pat_bytes(pattern_text[:64]))
    public_names: list[PatPublicName] = []
    referenced_names: list[PatPublicName] = []
    tail_bytes: tuple[int | None, ...] = ()
    idx = 4
    while idx < len(parts):
        token = parts[idx]
        public_match = _PAT_PUBLIC_RE.match(token)
        if public_match is not None and idx + 1 < len(parts):
            try:
                offset = int(public_match.group("offset"), 16)
            except ValueError:
                offset = 0
            public_names.append(PatPublicName(offset=offset, name=parts[idx + 1]))
            idx += 2
            continue
        if token.startswith("^") and idx + 1 < len(parts):
            try:
                ref_offset = int(token[1:], 16)
            except ValueError:
                ref_offset = 0
            referenced_names.append(PatPublicName(offset=ref_offset, name=parts[idx + 1]))
            idx += 2
            continue
        if _PAT_HEX_RE.fullmatch(token):
            tail_bytes = tuple(_decode_pat_bytes(token))
            idx += 1
            continue
        idx += 1
    if not public_names or module_length <= 0:
        return None
    comment_source_path, comment_compiler_name, comment_module_name = _parse_pat_comment_metadata(comment_text)
    return PatModule(
        source_path=comment_source_path or source_path,
        compiler_name=comment_compiler_name or _compiler_name_from_source_path(comment_source_path or source_path),
        module_name=comment_module_name or public_names[0].name,
        pattern_bytes=pattern_bytes,
        module_length=module_length,
        public_names=tuple(public_names),
        referenced_names=tuple(referenced_names),
        tail_bytes=tail_bytes,
    )


def format_pat_module_line(module: PatModule) -> str:
    head = _encode_pat_bytes(module.pattern_bytes)
    public_tokens = " ".join(f":{public.offset:04X} {public.name}" for public in module.public_names)
    ref_tokens = " ".join(f"^{ref.offset:04X} {ref.name}" for ref in module.referenced_names)
    tail = _encode_pat_bytes(module.tail_bytes)
    comment = _sanitize_pat_comment(_format_pat_comment(module))
    parts = [head, "00", "0000", f"{module.module_length:04X}", public_tokens]
    if ref_tokens:
        parts.append(ref_tokens)
    if tail:
        parts.append(tail)
    if comment:
        parts.append(f"; {comment}")
    return " ".join(part for part in parts if part).rstrip()


def _format_pat_comment(module: PatModule) -> str:
    parts = [f"mod={module.module_name}"]
    if module.source_path:
        parts.append(f"src={module.source_path}")
    if module.compiler_name:
        parts.append(f"compiler={module.compiler_name}")
    return " | ".join(parts)


def _parse_pat_comment_metadata(comment_text: str) -> tuple[str, str, str]:
    if not comment_text:
        return "", "", ""
    source_path = ""
    compiler_name = ""
    module_name = ""
    for part in (piece.strip() for piece in comment_text.split("|")):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "src":
            source_path = value
        elif key == "compiler":
            compiler_name = value
        elif key == "mod":
            module_name = value
    return source_path, compiler_name, module_name


def _compiler_name_from_source_path(source_path: str) -> str:
    lowered = source_path.replace("\\", "/").lower()
    if "microsoft c v5.1" in lowered:
        return "Microsoft C v5.1"
    if "microsoft c v5" in lowered:
        return "Microsoft C v5"
    if "microsoft c v6ax" in lowered:
        return "Microsoft C v6ax"
    if "borland" in lowered or "turbo " in lowered:
        return "Borland/Turbo"
    if "watcom" in lowered:
        return "Watcom"
    if "zortech" in lowered:
        return "Zortech"
    if "ida" in lowered or "flair" in lowered:
        return "IDA FLAIR"
    return ""


def normalized_pat_merge_name(name: str) -> str:
    match = _PAT_MERGE_NAME_RE.fullmatch(name)
    if match is not None:
        return match.group(1).lower()
    return name


def ensure_pat_from_omf_input(
    input_path: Path,
    cache_dir: Path,
    *,
    flair_root: Path | None = None,
) -> Path | None:
    suffix = input_path.suffix.lower()
    if suffix == ".pat" and input_path.exists():
        return input_path
    if suffix not in {".obj", ".lib"} or not input_path.exists():
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = _cache_key_for_file(input_path)
    out_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.pat"
    lines: list[str] = []
    
    try:
        if _run_local_plb(input_path, out_path, flair_root=flair_root):
            try:
                lines.extend(
                    line for line in out_path.read_text(errors="ignore").splitlines() if line.strip() and line.strip() != "---"
                )
            except OSError:
                pass
    except Exception:
        # FLAIR attempt failed - continue to fallback
        pass
    
    if suffix == ".obj":
        fallback_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.fallback.pat"
        try:
            if generate_pat_from_omf_obj(input_path, fallback_path) > 0:
                try:
                    lines.extend(
                        line
                        for line in fallback_path.read_text(errors="ignore").splitlines()
                        if line.strip() and line.strip() != "---"
                    )
                except OSError:
                    pass
                finally:
                    try:
                        fallback_path.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception:
            # Fallback generation failed - continue
            pass
    elif suffix == ".lib":
        fallback_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.fallback.pat"
        try:
            if generate_pat_from_omf_lib(input_path, fallback_path) > 0:
                try:
                    lines.extend(
                        line
                        for line in fallback_path.read_text(errors="ignore").splitlines()
                        if line.strip() and line.strip() != "---"
                    )
                except OSError:
                    pass
                finally:
                    try:
                        fallback_path.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception:
            # Fallback generation failed - continue
            pass
    
    if not lines:
        return None
    deduped_lines = list(dict.fromkeys(lines))
    out_path.write_text("".join(f"{line}\n" for line in deduped_lines) + "---\n")
    return out_path


def discover_local_pat_matches(
    binary_path: Path,
    project,
    *,
    flair_root: Path | None = None,
    max_candidate_inputs: int = 32,
    max_pat_modules: int = 512,
    backend: str | None = None,
) -> LocalPatMatchResult:
    if signature_matching_disabled():
        return LocalPatMatchResult({}, {}, ())
    candidate_inputs = _discover_candidate_pat_inputs(binary_path)[:max_candidate_inputs]
    if not candidate_inputs:
        return LocalPatMatchResult({}, {}, ())

    selected_backend = _normalize_pat_backend_choice(backend)
    cache_dir = _pick_pat_cache_dir(binary_path)
    modules: list[PatModule | CachedPatRegexSpec] = []
    used_generated = False
    used_plain_pat = False
    for candidate in candidate_inputs:
        pat_path = ensure_pat_from_omf_input(candidate, cache_dir, flair_root=flair_root)
        if pat_path is None:
            continue
        used_generated |= pat_path != candidate
        used_plain_pat |= pat_path == candidate
        modules.extend(load_cached_pat_regex_specs(pat_path, cache_dir))
        if len(modules) >= max_pat_modules:
            modules = modules[:max_pat_modules]
            break
    if not modules:
        return LocalPatMatchResult({}, {}, ())

    image = _load_project_image(project)
    if image is None:
        return LocalPatMatchResult({}, {}, ())
    base_addr, image_bytes = image
    code_labels, code_ranges, matched_compiler_names = match_pat_modules(
        image_bytes,
        base_addr,
        modules,
        backend=selected_backend,
    )
    source_formats: list[str] = []
    if code_labels:
        if used_plain_pat:
            source_formats.append("local_pat")
        if used_generated:
            source_formats.append("local_omf_pat")
        source_formats.append(f"pat_backend:{selected_backend}")
    return LocalPatMatchResult(code_labels, code_ranges, tuple(source_formats), matched_compiler_names)


def match_pat_modules(
    image_bytes: bytes,
    base_addr: int,
    modules: tuple[PatModule | CachedPatRegexSpec, ...] | list[PatModule | CachedPatRegexSpec],
    *,
    backend: str | None = None,
) -> tuple[dict[int, str], dict[int, tuple[int, int]], tuple[str, ...]]:
    selected_backend = _normalize_pat_backend_choice(backend)
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    matched_compiler_names: list[str] = []
    for module in modules:
        hits = _find_pat_matches(image_bytes, module, backend=selected_backend)
        if len(hits) != 1:
            continue
        for compiler_name in (
            part.strip()
            for part in getattr(module, "compiler_name", "").split(" || ")
            if part.strip()
        ):
            if compiler_name not in matched_compiler_names:
                matched_compiler_names.append(compiler_name)
        start_off = hits[0]
        match_addr = base_addr + start_off
        public_names = module.public_names
        module_length = module.module_length
        if public_names:
            first_public = min(public_names, key=lambda pub: pub.offset)
            code_start = match_addr + first_public.offset
            code_end = match_addr + module_length
            if code_end > code_start:
                code_ranges.setdefault(code_start, (code_start, code_end))
        for public_name in public_names:
            linear = match_addr + public_name.offset
            code_labels.setdefault(linear, public_name.name.lstrip("_"))
    return code_labels, code_ranges, tuple(matched_compiler_names)


def generate_pat_from_omf_obj(obj_path: Path, out_path: Path) -> int:
    try:
        lines = _generate_pat_lines_from_omf_blob(
            obj_path.read_bytes(),
            source_name=obj_path.name,
            provenance_source=str(obj_path),
            provenance_compiler=_compiler_name_from_source_path(str(obj_path)),
        )
        out_path.write_text("".join(f"{line}\n" for line in lines) + "---\n")
        return len(lines)
    except Exception:
        # Silently fail - return 0 patterns generated
        # Caller will handle fallback/error reporting
        return 0


def generate_pat_from_omf_lib(lib_path: Path, out_path: Path) -> int:
    try:
        lines: list[str] = []
        # Check if this is actually a Microsoft OMF library before attempting extraction
        blob = lib_path.read_bytes()
        lib_format = _detect_lib_format(blob)
        
        if lib_format != "microsoft":
            # Unsupported format - don't crash, just return 0
            return 0
        
        for module in extract_omf_modules_from_lib(lib_path):
            lines.extend(
                _generate_pat_lines_from_omf_blob(
                    module.data,
                    source_name=module.module_name,
                    provenance_source=str(lib_path),
                    provenance_compiler=_compiler_name_from_source_path(str(lib_path)),
                )
            )
        
        if lines:
            out_path.write_text("".join(f"{line}\n" for line in lines) + "---\n")
        return len(lines)
    except Exception:
        # Silently fail - return 0 patterns generated
        # Caller will handle fallback/error reporting  
        return 0


def extract_omf_modules_from_lib(lib_path: Path) -> tuple[OMFModuleBlob, ...]:
    return parse_microsoft_lib(lib_path).modules


def parse_omf_lib(lib_path: Path) -> MicrosoftLibMetadata:
    """
    Parse a page-based OMF library container.

    Borland/Turbo C libraries use the same archive shell we already support for
    Microsoft-style OMF libraries, so keep one parser and expose a vendor-neutral
    name for callers that only care about the outer `.LIB` container.
    """

    return parse_microsoft_lib(lib_path)


def get_lib_format_info(lib_path: Path) -> dict[str, str | int]:
    """
    Get diagnostic information about a library file format.
    
    Returns a dict with:
    - format: "microsoft", "intel", "unknown", or None
    - size: file size in bytes
    - header_hex: first 4 bytes as hex string
    - supported: True if format is currently supported, False otherwise
    """
    if not lib_path.exists():
        return {"error": "File not found"}
    
    try:
        blob = lib_path.read_bytes()
        lib_format = _detect_lib_format(blob)
        
        header_hex = blob[:4].hex() if len(blob) >= 4 else blob.hex()
        supported = lib_format == "microsoft"
        
        return {
            "format": lib_format,
            "size": len(blob),
            "header_hex": header_hex,
            "supported": supported,
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:60]}"}


def _detect_lib_format(blob: bytes) -> str | None:
    """
    Detect the format of a library file.
    
    Returns:
        - "microsoft": Microsoft OMF format (0xF0 header)
        - "intel": Intel iC-86 format (0xA4 0x07 header)
        - "unknown": Other format (unrecognized header)
        - None: File too small or empty
    """
    if len(blob) < 2:
        return None
    
    first_byte = blob[0]
    
    # Microsoft OMF format
    if first_byte == 0xF0:
        return "microsoft"
    
    # Intel iC-86 / Intel IA-86 format (ARN - Archive Librarian format)
    if len(blob) >= 4 and blob[:2] == b'\xa4\x07':
        return "intel"
    
    # Unknown/unsupported format
    if len(blob) >= 4:
        return "unknown"
    
    return None


def parse_microsoft_lib(lib_path: Path) -> MicrosoftLibMetadata:
    # Check if file exists first
    if not lib_path.exists():
        empty_header = MicrosoftLibHeader(page_size=0, dictionary_offset=0, dictionary_blocks=0, case_sensitive=False)
        return MicrosoftLibMetadata(header=empty_header, modules=(), dictionary_entries=(), extended_records=())
    
    blob = lib_path.read_bytes()
    
    # Detect and handle unsupported formats gracefully
    lib_format = _detect_lib_format(blob)
    if lib_format is None:
        empty_header = MicrosoftLibHeader(page_size=0, dictionary_offset=0, dictionary_blocks=0, case_sensitive=False)
        return MicrosoftLibMetadata(header=empty_header, modules=(), dictionary_entries=(), extended_records=())
    
    # For Intel and other unsupported formats, return empty but don't crash
    if lib_format != "microsoft":
        # Could add support for other formats here in the future
        # For now, return empty result with format hint in header page_size (abuse I know, but keeps API stable)
        empty_header = MicrosoftLibHeader(page_size=-1, dictionary_offset=0, dictionary_blocks=0, case_sensitive=False)
        return MicrosoftLibMetadata(header=empty_header, modules=(), dictionary_entries=(), extended_records=())
    
    # Parse Microsoft OMF format
    if len(blob) < 16:
        empty_header = MicrosoftLibHeader(page_size=0, dictionary_offset=0, dictionary_blocks=0, case_sensitive=False)
        return MicrosoftLibMetadata(header=empty_header, modules=(), dictionary_entries=(), extended_records=())
    
    header = _parse_microsoft_lib_header(blob)
    page_size = header.page_size
    if page_size <= 0 or len(blob) < page_size:
        return MicrosoftLibMetadata(header=header, modules=(), dictionary_entries=(), extended_records=())
    dict_offset = header.dictionary_offset
    if dict_offset <= 0 or dict_offset > len(blob):
        dict_offset = len(blob)
    dictionary_entries = _parse_microsoft_lib_dictionary(blob, header)
    extended_records = _parse_microsoft_lib_extended_dict(blob, header)
    deps_by_page = {record.page_number: record.dependency_indexes for record in extended_records}
    modules: list[OMFModuleBlob] = []
    offset = page_size
    while offset < dict_offset:
        if offset + 3 > len(blob):
            break
        record_type = blob[offset]
        if record_type in {0x00, 0xF1}:
            offset = _align_up(offset + 1, page_size)
            continue
        module_end = _find_omf_module_end(blob, offset, dict_offset)
        if module_end is None:
            break
        module_blob = blob[offset:module_end]
        module_name = _peek_omf_module_name(module_blob) or f"{lib_path.stem}@0x{offset:x}"
        page_number = offset // page_size
        modules.append(
            OMFModuleBlob(
                module_name=module_name,
                data=module_blob,
                page_offset=offset,
                page_number=page_number,
                dependency_indexes=deps_by_page.get(page_number, ()),
            )
        )
        offset = _align_up(module_end, page_size)
    return MicrosoftLibMetadata(
        header=header,
        modules=tuple(modules),
        dictionary_entries=dictionary_entries,
        extended_records=extended_records,
    )


def enumerate_microsoft_lib_dictionary_symbols(lib_path: Path) -> tuple[MicrosoftLibDictionaryEntry, ...]:
    return parse_microsoft_lib(lib_path).dictionary_entries


def enumerate_omf_lib_dictionary_symbols(lib_path: Path) -> tuple[MicrosoftLibDictionaryEntry, ...]:
    return parse_omf_lib(lib_path).dictionary_entries


def lookup_microsoft_lib_symbol(lib_path: Path, symbol_name: str) -> MicrosoftLibDictionaryEntry | None:
    metadata = parse_microsoft_lib(lib_path)
    entry = _lookup_microsoft_lib_symbol_in_metadata(metadata, symbol_name)
    if entry is None and not metadata.header.case_sensitive:
        folded = symbol_name.casefold()
        for candidate in metadata.dictionary_entries:
            if candidate.symbol_name.casefold() == folded:
                return candidate
    return entry


def lookup_omf_lib_symbol(lib_path: Path, symbol_name: str) -> MicrosoftLibDictionaryEntry | None:
    return lookup_microsoft_lib_symbol(lib_path, symbol_name)


def _build_pat_line(
    function_bytes: bytes | list[int | None],
    *,
    public_name: str,
    module_name: str,
    referenced_names: tuple[PatPublicName, ...] = (),
) -> str | None:
    if len(function_bytes) < 4:
        return None
    head = list(function_bytes[:32])
    while len(head) < 32:
        head.append(None)
    tail = list(function_bytes[32:])
    ref_tokens = " ".join(f"^{ref.offset:04X} {ref.name}" for ref in _dedupe_referenced_names(referenced_names))
    line = (
        f"{_encode_pat_bytes(head)} 00 0000 {len(function_bytes):04X} "
        f":0000 {public_name}"
    )
    if ref_tokens:
        line += f" {ref_tokens}"
    line += f" {_encode_pat_bytes(tail)} ; {module_name}"
    return line.rstrip()


def _wildcard_zero_displacement_control_transfers(
    function_bytes: list[int | None],
) -> list[int | None]:
    rewritten = list(function_bytes)
    limit = len(rewritten)
    index = 0
    while index < limit:
        opcode = rewritten[index]
        if opcode == 0xE8 or opcode == 0xE9:
            if index + 2 < limit and rewritten[index + 1] == 0 and rewritten[index + 2] == 0:
                rewritten[index + 1] = None
                rewritten[index + 2] = None
            index += 3
            continue
        if opcode == 0x9A or opcode == 0xEA:
            if index + 4 < limit and all(rewritten[index + off] == 0 for off in range(1, 5)):
                for off in range(1, 5):
                    rewritten[index + off] = None
            index += 5
            continue
        index += 1
    return rewritten


def _wildcard_far_transfer_opcode_variants(
    function_bytes: list[int | None],
) -> list[int | None]:
    """
    IDA FLAIR PAT guidance for 16-bit x86 says external far calls may be
    linker-rewritten from:

        9A ........

    into:

        90 0E E8 ....

    The target bytes are already fixup-wildcarded. To keep the object-module
    pattern matchable against the linked image, the far-transfer opcode byte
    itself must also be allowed to vary.
    """

    rewritten = list(function_bytes)
    limit = len(rewritten)
    index = 0
    while index + 4 < limit:
        opcode = rewritten[index]
        if opcode in {0x9A, 0xEA} and all(rewritten[index + off] is None for off in range(1, 5)):
            rewritten[index] = None
            index += 5
            continue
        index += 1
    return rewritten


def _is_microsoft_c_compiler_name(compiler_name: str) -> bool:
    return "microsoft c" in compiler_name.lower()


def _looks_like_msvc_fpu_runtime(
    public_name: str,
    referenced_names: tuple[PatPublicName, ...],
    *,
    compiler_name: str,
) -> bool:
    if not _is_microsoft_c_compiler_name(compiler_name):
        return False
    lowered = public_name.lower()
    if lowered.startswith(("__f", "__af", "__anf", "b$")):
        return True
    return any(ref.name.lower().startswith(("__f", "__af", "__anf", "b$f")) for ref in referenced_names)


def _x87_emulator_variant_bytes(function_bytes: list[int | None]) -> list[int | None]:
    """
    MS-DOS x87 emulator encoding observed in Microsoft C 16-bit runtimes.

    Ghidra issue #2427 and MS DOS reverse-engineering notes use this mapping:

      9B D9 -> CD 35
      9B DA -> CD 36
      9B DB -> CD 37
      9B DC -> CD 38
      9B DD -> CD 39
      9B DE -> CD 3A
      9B DF -> CD 3B
      9B 26 -> CD 3C
      90 9B -> CD 3D

    This is emitted only as an alternate PAT row for runtime helpers so exact
    matching can see both the direct x87 and emulator-linked encodings.
    """

    mapping = {
        (0x9B, 0xD9): (0xCD, 0x35),
        (0x9B, 0xDA): (0xCD, 0x36),
        (0x9B, 0xDB): (0xCD, 0x37),
        (0x9B, 0xDC): (0xCD, 0x38),
        (0x9B, 0xDD): (0xCD, 0x39),
        (0x9B, 0xDE): (0xCD, 0x3A),
        (0x9B, 0xDF): (0xCD, 0x3B),
        (0x9B, 0x26): (0xCD, 0x3C),
        (0x90, 0x9B): (0xCD, 0x3D),
    }
    rewritten = list(function_bytes)
    changed = False
    index = 0
    while index + 1 < len(rewritten):
        pair = (rewritten[index], rewritten[index + 1])
        if pair in mapping:
            repl0, repl1 = mapping[pair]
            rewritten[index] = repl0
            rewritten[index + 1] = repl1
            changed = True
            index += 2
            continue
        index += 1
    return rewritten if changed else function_bytes


def _parse_omf_obj(obj_path: Path) -> tuple[str, list[_OMFSegment], list[_OMFPublic], list[_OMFFixupRef]]:
    return _parse_omf_blob(obj_path.read_bytes(), module_name_hint=obj_path.stem)


def _parse_omf_blob(
    blob: bytes,
    *,
    module_name_hint: str,
) -> tuple[str, list[_OMFSegment], list[_OMFPublic], list[_OMFFixupRef]]:
    lnames: list[str] = [""]
    segments: list[_OMFSegment] = []
    publics: list[_OMFPublic] = []
    external_names: list[str] = [""]
    fixup_refs: list[_OMFFixupRef] = []
    target_threads: dict[int, tuple[int, int]] = {}
    frame_threads: dict[int, tuple[int, int]] = {}
    last_data_context: _OMFDataRecordContext | None = None
    module_name = module_name_hint
    for record_type, payload in _iter_omf_records(blob):
        if record_type == 0x80 and payload:
            name_len = payload[0]
            module_name = payload[1 : 1 + name_len].decode("latin1", errors="ignore") or module_name
        elif record_type in {0x96, 0xCA}:
            lnames.extend(_parse_lnames(payload))
        elif record_type == 0x98:
            segments.append(_parse_segdef(payload, lnames))
        elif record_type in {0x90, 0xB6}:
            publics.extend(_parse_pubdef(payload))
        elif record_type in {0x8C, 0xB4}:
            external_names.extend(_parse_extdef_names(payload))
        elif record_type in {0xB0, 0xB8}:
            external_names.extend(_parse_comdef_names(payload))
        elif record_type == 0xA0:
            last_data_context = _apply_ledata(payload, segments)
        elif record_type == 0x9C and last_data_context is not None:
            fixup_refs.extend(
                _parse_fixupp_refs(
                    payload,
                    last_data_context,
                    external_names,
                    target_threads,
                    frame_threads,
                )
            )
    return module_name, segments, publics, fixup_refs


def _generate_pat_lines_from_omf_blob(
    blob: bytes,
    *,
    source_name: str,
    provenance_source: str = "",
    provenance_compiler: str = "",
) -> list[str]:
    module_name, segments, publics, fixup_refs = _parse_omf_blob(blob, module_name_hint=Path(source_name).stem)
    lines: list[str] = []
    publics_by_segment: dict[int, list[_OMFPublic]] = {}
    for public in publics:
        publics_by_segment.setdefault(public.seg_index, []).append(public)
    refs_by_segment: dict[int, list[_OMFFixupRef]] = {}
    for fixup_ref in fixup_refs:
        refs_by_segment.setdefault(fixup_ref.seg_index, []).append(fixup_ref)
    for seg_index, seg_publics in sorted(publics_by_segment.items()):
        if seg_index <= 0 or seg_index > len(segments):
            continue
        segment = segments[seg_index - 1]
        if not _segment_looks_like_code(segment):
            continue
        seg_publics.sort(key=lambda item: item.offset)
        seg_limit = segment.max_written_end or len(segment.data)
        segment_refs = sorted(refs_by_segment.get(seg_index, ()), key=lambda item: (item.offset, item.name))
        for index, public in enumerate(seg_publics):
            start = public.offset
            next_public = seg_publics[index + 1].offset if index + 1 < len(seg_publics) else seg_limit
            end = max(start, min(next_public, seg_limit))
            if end <= start:
                continue
            func_bytes: list[int | None] = list(bytes(segment.data[start:end]))
            if sum(1 for _ in func_bytes[:32]) < 4:
                continue
            for fixup_ref in segment_refs:
                if not (start <= fixup_ref.offset < end):
                    continue
                local_off = fixup_ref.offset - start
                for idx in range(local_off, min(local_off + fixup_ref.width, len(func_bytes))):
                    func_bytes[idx] = None
            function_refs = tuple(
                PatPublicName(offset=fixup_ref.offset - start, name=fixup_ref.name)
                for fixup_ref in segment_refs
                if start <= fixup_ref.offset < end and fixup_ref.name
            )
            line = _build_pat_line(
                func_bytes,
                public_name=public.name,
                module_name=f"{module_name}:{public.name}",
                referenced_names=function_refs,
            )
            if line is not None:
                line = line.rsplit(" ; ", 1)[0] + " ; " + _sanitize_pat_comment(
                    " | ".join(
                        part
                        for part in (
                            f"mod={module_name}:{public.name}",
                            f"src={provenance_source}" if provenance_source else "",
                            f"compiler={provenance_compiler}" if provenance_compiler else "",
                        )
                        if part
                    )
                )
                lines.append(line)
            wildcard_ctf_bytes = _wildcard_zero_displacement_control_transfers(func_bytes)
            if wildcard_ctf_bytes != func_bytes:
                wildcard_line = _build_pat_line(
                    wildcard_ctf_bytes,
                    public_name=public.name,
                    module_name=f"{module_name}:{public.name}",
                    referenced_names=function_refs,
                )
                if wildcard_line is not None:
                    wildcard_line = wildcard_line.rsplit(" ; ", 1)[0] + " ; " + _sanitize_pat_comment(
                        " | ".join(
                            part
                            for part in (
                                f"mod={module_name}:{public.name}",
                                f"src={provenance_source}" if provenance_source else "",
                                f"compiler={provenance_compiler}" if provenance_compiler else "",
                            )
                            if part
                        )
                    )
                    lines.append(wildcard_line)
            wildcard_far_transfer_bytes = _wildcard_far_transfer_opcode_variants(func_bytes)
            if wildcard_far_transfer_bytes != func_bytes and wildcard_far_transfer_bytes != wildcard_ctf_bytes:
                wildcard_far_transfer_line = _build_pat_line(
                    wildcard_far_transfer_bytes,
                    public_name=public.name,
                    module_name=f"{module_name}:{public.name}",
                    referenced_names=function_refs,
                )
                if wildcard_far_transfer_line is not None:
                    wildcard_far_transfer_line = wildcard_far_transfer_line.rsplit(" ; ", 1)[0] + " ; " + _sanitize_pat_comment(
                        " | ".join(
                            part
                            for part in (
                                f"mod={module_name}:{public.name}",
                                f"src={provenance_source}" if provenance_source else "",
                                f"compiler={provenance_compiler}" if provenance_compiler else "",
                            )
                            if part
                        )
                    )
                    lines.append(wildcard_far_transfer_line)
            if _looks_like_msvc_fpu_runtime(
                public.name,
                function_refs,
                compiler_name=provenance_compiler,
            ):
                x87_emulator_bytes = _x87_emulator_variant_bytes(func_bytes)
                if x87_emulator_bytes != func_bytes and x87_emulator_bytes != wildcard_ctf_bytes and x87_emulator_bytes != wildcard_far_transfer_bytes:
                    emulator_line = _build_pat_line(
                        x87_emulator_bytes,
                        public_name=public.name,
                        module_name=f"{module_name}:{public.name}",
                        referenced_names=function_refs,
                    )
                    if emulator_line is not None:
                        emulator_line = emulator_line.rsplit(" ; ", 1)[0] + " ; " + _sanitize_pat_comment(
                            " | ".join(
                                part
                                for part in (
                                    f"mod={module_name}:{public.name}",
                                    f"src={provenance_source}" if provenance_source else "",
                                    f"compiler={provenance_compiler}" if provenance_compiler else "",
                                )
                                if part
                            )
                        )
                        lines.append(emulator_line)
    return lines


def _iter_omf_records(blob: bytes):
    offset = 0
    while offset + 3 <= len(blob):
        record_type = blob[offset]
        record_length = blob[offset + 1] | (blob[offset + 2] << 8)
        if record_length <= 0 or offset + 3 + record_length > len(blob):
            break
        payload = blob[offset + 3 : offset + 3 + record_length - 1]
        yield record_type, payload
        offset += 3 + record_length


def _find_omf_module_end(blob: bytes, start: int, limit: int) -> int | None:
    offset = start
    while offset + 3 <= limit:
        record_length = blob[offset + 1] | (blob[offset + 2] << 8)
        record_end = offset + 3 + record_length
        if record_length <= 0 or record_end > limit:
            return None
        if blob[offset] == 0x8A:
            return record_end
        offset = record_end
    return None


def _peek_omf_module_name(blob: bytes) -> str | None:
    if len(blob) < 5 or blob[0] != 0x80:
        return None
    name_len = blob[3]
    if 4 + name_len > len(blob):
        return None
    return blob[4 : 4 + name_len].decode("latin1", errors="ignore") or None


def _parse_microsoft_lib_header(blob: bytes) -> MicrosoftLibHeader:
    record_length = int.from_bytes(blob[1:3], "little")
    page_size = record_length + 3
    dictionary_offset = int.from_bytes(blob[3:7], "little")
    dictionary_blocks = int.from_bytes(blob[7:9], "little")
    flags = blob[9] if len(blob) > 9 else 0
    return MicrosoftLibHeader(
        page_size=page_size,
        dictionary_offset=dictionary_offset,
        dictionary_blocks=dictionary_blocks,
        case_sensitive=bool(flags & 0x01),
    )


def _parse_microsoft_lib_extended_dict(
    blob: bytes,
    header: MicrosoftLibHeader,
) -> tuple[MicrosoftLibExtendedRecord, ...]:
    if header.dictionary_blocks <= 0 or header.dictionary_offset <= 0:
        return ()
    dict_end = header.dictionary_offset + header.dictionary_blocks * 512
    if dict_end + 5 > len(blob):
        return ()
    if blob[dict_end] != 0xF2:
        return ()
    record_length = int.from_bytes(blob[dict_end + 1 : dict_end + 3], "little")
    record_end = dict_end + 3 + record_length
    if record_end > len(blob):
        return ()
    payload = blob[dict_end + 3 : record_end - 1]
    if len(payload) < 2:
        return ()
    module_count = int.from_bytes(payload[:2], "little")
    table_off = 2
    table_size = module_count * 4
    if len(payload) < table_off + table_size:
        return ()
    records: list[MicrosoftLibExtendedRecord] = []
    for index in range(module_count):
        entry_off = table_off + index * 4
        page_number = int.from_bytes(payload[entry_off : entry_off + 2], "little")
        dependency_offset = int.from_bytes(payload[entry_off + 2 : entry_off + 4], "little")
        dependency_indexes = _parse_extended_dependency_list(payload, dependency_offset)
        records.append(
            MicrosoftLibExtendedRecord(
                page_number=page_number,
                dependency_offset=dependency_offset,
                dependency_indexes=dependency_indexes,
            )
        )
    return tuple(records)


def _parse_extended_dependency_list(payload: bytes, dependency_offset: int) -> tuple[int, ...]:
    if dependency_offset <= 0 or dependency_offset >= len(payload):
        return ()
    values: list[int] = []
    off = dependency_offset
    while off + 2 <= len(payload):
        value = int.from_bytes(payload[off : off + 2], "little")
        off += 2
        if value == 0:
            break
        values.append(value)
    return tuple(values)


def _parse_microsoft_lib_dictionary(
    blob: bytes,
    header: MicrosoftLibHeader,
) -> tuple[MicrosoftLibDictionaryEntry, ...]:
    if header.dictionary_blocks <= 0 or header.dictionary_offset <= 0:
        return ()
    dict_start = header.dictionary_offset
    dict_end = min(len(blob), dict_start + header.dictionary_blocks * 512)
    if dict_end - dict_start < 512:
        return ()
    entries: dict[tuple[str, int], MicrosoftLibDictionaryEntry] = {}
    page_count = (dict_end - dict_start) // 512
    for page_index in range(page_count):
        page_off = dict_start + page_index * 512
        page = blob[page_off : page_off + 512]
        if len(page) < 39:
            continue
        bucket_table = page[:38]
        for bucket_index in range(37):
            pointer = bucket_table[bucket_index]
            if pointer == 0:
                continue
            entry = _parse_microsoft_lib_dictionary_entry(page, pointer * 2, page_index, bucket_index)
            if entry is None:
                continue
            entries.setdefault((entry.symbol_name, entry.module_page), entry)
    return tuple(sorted(entries.values(), key=lambda item: (item.symbol_name.lower(), item.module_page, item.page_index, item.bucket_index)))


def _parse_microsoft_lib_dictionary_entry(
    page: bytes,
    offset: int,
    page_index: int,
    bucket_index: int,
) -> MicrosoftLibDictionaryEntry | None:
    if offset <= 0 or offset + 3 > len(page):
        return None
    name_len = page[offset]
    name_start = offset + 1
    name_end = name_start + name_len
    if name_len <= 0 or name_end + 2 > len(page):
        return None
    symbol_name = page[name_start:name_end].decode("latin1", errors="ignore")
    if not symbol_name:
        return None
    module_page = int.from_bytes(page[name_end : name_end + 2], "little")
    if module_page <= 0:
        return None
    return MicrosoftLibDictionaryEntry(
        symbol_name=symbol_name,
        module_page=module_page,
        page_index=page_index,
        bucket_index=bucket_index,
    )


def _lookup_microsoft_lib_symbol_in_metadata(
    metadata: MicrosoftLibMetadata,
    symbol_name: str,
) -> MicrosoftLibDictionaryEntry | None:
    entries = metadata.dictionary_entries
    header = metadata.header
    if not entries or header.dictionary_blocks <= 0:
        return None
    page_index, page_index_delta, bucket_index, bucket_index_delta = _hash_microsoft_lib_symbol(
        symbol_name,
        header.dictionary_blocks,
        case_sensitive=header.case_sensitive,
    )
    if page_index_delta <= 0 or bucket_index_delta <= 0:
        return None
    entries_by_slot = {(entry.page_index, entry.bucket_index): entry for entry in entries}
    current_page = page_index
    current_bucket = bucket_index
    visited: set[tuple[int, int]] = set()
    for _page_try in range(header.dictionary_blocks):
        for _bucket_try in range(37):
            slot = (current_page, current_bucket)
            if slot in visited:
                break
            visited.add(slot)
            entry = entries_by_slot.get(slot)
            if entry is None:
                return None
            if _microsoft_lib_symbol_equals(entry.symbol_name, symbol_name, case_sensitive=header.case_sensitive):
                return entry
            current_bucket = (current_bucket + bucket_index_delta) % 37
        current_page = (current_page + page_index_delta) % header.dictionary_blocks
    return None


def _hash_microsoft_lib_symbol(
    symbol_name: str,
    dictionary_pages: int,
    *,
    case_sensitive: bool,
) -> tuple[int, int, int, int]:
    if dictionary_pages <= 0:
        return 0, 0, 0, 0
    name_bytes = symbol_name.encode("latin1", errors="ignore")
    if not case_sensitive:
        name_bytes = bytes((byte | 0x20) if 0x41 <= byte <= 0x5A else byte for byte in name_bytes)
    page_index = 0
    page_index_delta = 0
    bucket_index = 0
    bucket_index_delta = 0
    if not name_bytes:
        return 0, 1, 0, 1
    for forward, reverse in zip(name_bytes, reversed(name_bytes), strict=True):
        page_index = ((page_index << 2) ^ forward) & 0xFFFFFFFF
        bucket_index_delta = ((bucket_index_delta >> 2) ^ forward) & 0xFFFFFFFF
        bucket_index = ((bucket_index >> 2) ^ reverse) & 0xFFFFFFFF
        page_index_delta = ((page_index_delta << 2) ^ reverse) & 0xFFFFFFFF
    page_index %= dictionary_pages
    page_index_delta %= dictionary_pages
    if page_index_delta == 0:
        page_index_delta = 1
    bucket_index %= 37
    bucket_index_delta %= 37
    if bucket_index_delta == 0:
        bucket_index_delta = 1
    return page_index, page_index_delta, bucket_index, bucket_index_delta


def _microsoft_lib_symbol_equals(left: str, right: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return left == right
    return left.casefold() == right.casefold()


def _parse_lnames(payload: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        names.append(payload[offset : offset + name_len].decode("latin1", errors="ignore"))
        offset += name_len
    return names


def _parse_segdef(payload: bytes, lnames: list[str]) -> _OMFSegment:
    offset = 0
    acbp = payload[offset]
    offset += 1
    use32 = bool(acbp & 0x01)
    seg_length_size = 4 if use32 else 2
    declared_length = int.from_bytes(payload[offset : offset + seg_length_size], "little")
    offset += seg_length_size
    seg_name_index, offset = _read_omf_index(payload, offset)
    class_name_index, offset = _read_omf_index(payload, offset)
    _, offset = _read_omf_index(payload, offset)
    seg_name = lnames[seg_name_index] if seg_name_index < len(lnames) else ""
    class_name = lnames[class_name_index] if class_name_index < len(lnames) else ""
    return _OMFSegment(
        name=seg_name,
        class_name=class_name,
        declared_length=declared_length,
        data=bytearray(declared_length),
        max_written_end=0,
    )


def _parse_pubdef(payload: bytes) -> list[_OMFPublic]:
    offset = 0
    group_index, offset = _read_omf_index(payload, offset)
    seg_index, offset = _read_omf_index(payload, offset)
    if group_index == 0 and seg_index == 0:
        offset += 2
    publics: list[_OMFPublic] = []
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        name = payload[offset : offset + name_len].decode("latin1", errors="ignore")
        offset += name_len
        if offset + 2 > len(payload):
            break
        public_offset = int.from_bytes(payload[offset : offset + 2], "little")
        offset += 2
        _, offset = _read_omf_index(payload, offset)
        if seg_index:
            publics.append(_OMFPublic(seg_index=seg_index, offset=public_offset, name=name))
    return publics


def _apply_ledata(payload: bytes, segments: list[_OMFSegment]) -> _OMFDataRecordContext | None:
    seg_index, offset = _read_omf_index(payload, 0)
    if seg_index <= 0 or seg_index > len(segments) or offset + 2 > len(payload):
        return None
    data_offset = int.from_bytes(payload[offset : offset + 2], "little")
    offset += 2
    data = payload[offset:]
    segment = segments[seg_index - 1]
    end = data_offset + len(data)
    if end > len(segment.data):
        segment.data.extend(b"\x00" * (end - len(segment.data)))
    segment.data[data_offset:end] = data
    segment.max_written_end = max(segment.max_written_end, end)
    return _OMFDataRecordContext(seg_index=seg_index, data_offset=data_offset, data_length=len(data))


def _parse_extdef_names(payload: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        name = payload[offset : offset + name_len].decode("latin1", errors="ignore")
        offset += name_len
        _type_index, offset = _read_omf_index(payload, offset)
        if name:
            names.append(name)
    return names


def _parse_comdef_names(payload: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        name = payload[offset : offset + name_len].decode("latin1", errors="ignore")
        offset += name_len
        _type_index, offset = _read_omf_index(payload, offset)
        if offset >= len(payload):
            break
        communal_kind = payload[offset]
        offset += 1
        _size, offset = _read_omf_numeric_value(payload, offset)
        if communal_kind == 0x61:
            _count, offset = _read_omf_numeric_value(payload, offset)
        if name:
            names.append(name)
    return names


def _parse_fixupp_refs(
    payload: bytes,
    last_data_context: _OMFDataRecordContext,
    external_names: list[str],
    target_threads: dict[int, tuple[int, int]],
    frame_threads: dict[int, tuple[int, int]],
) -> list[_OMFFixupRef]:
    refs: list[_OMFFixupRef] = []
    offset = 0
    while offset < len(payload):
        first = payload[offset]
        if first & 0x80 == 0:
            offset = _consume_fixupp_thread(payload, offset, target_threads, frame_threads)
            continue
        if offset + 3 > len(payload):
            break
        locat = int.from_bytes(payload[offset : offset + 2], "little")
        offset += 2
        fixdat = payload[offset]
        offset += 1
        _frame_method, offset = _consume_fixupp_frame(payload, offset, fixdat, frame_threads)
        target_method, target_index, offset = _consume_fixupp_target(payload, offset, fixdat, target_threads)
        location_kind = (locat >> 10) & 0x0F
        displacement_size = _omf_fixup_width_from_location_kind(location_kind)
        if not (fixdat & 0x04):
            offset = min(len(payload), offset + displacement_size)
        dro = locat & 0x03FF
        if dro >= last_data_context.data_length:
            continue
        target_name = ""
        if target_method == 2 and 0 < target_index < len(external_names):
            target_name = external_names[target_index]
        refs.append(
            _OMFFixupRef(
                seg_index=last_data_context.seg_index,
                offset=last_data_context.data_offset + dro,
                width=displacement_size,
                name=target_name,
            )
        )
    return refs


def _omf_fixup_width_from_location_kind(location_kind: int) -> int:
    """
    OMF LOCAT.LOC width classes for x86, per linker/reference behavior.

      0  -> low-order byte
      1  -> 16-bit offset
      2  -> 16-bit base segment/group
      3  -> ptr16:16
      5  -> same as 1
      9  -> 32-bit offset
      11 -> ptr16:32
      13 -> same as 9

    Unsupported/unknown kinds fall back conservatively to 2 bytes to avoid
    under-consuming the common 16-bit displacement field shape.
    """

    width_by_kind = {
        0: 1,
        1: 2,
        2: 2,
        3: 4,
        5: 2,
        9: 4,
        11: 6,
        13: 4,
    }
    return width_by_kind.get(location_kind, 2)


def _consume_fixupp_thread(
    payload: bytes,
    offset: int,
    target_threads: dict[int, tuple[int, int]],
    frame_threads: dict[int, tuple[int, int]],
) -> int:
    thread_byte = payload[offset]
    offset += 1
    is_frame = bool(thread_byte & 0x40)
    method = (thread_byte >> 2) & 0x07
    thread_no = thread_byte & 0x03
    index = 0
    if method < 3:
        index, offset = _read_omf_index(payload, offset)
    if is_frame:
        frame_threads[thread_no] = (method, index)
    else:
        target_threads[thread_no] = (method, index)
    return offset


def _consume_fixupp_frame(
    payload: bytes,
    offset: int,
    fixdat: int,
    frame_threads: dict[int, tuple[int, int]],
) -> tuple[int | None, int]:
    if fixdat & 0x80:
        thread_no = (fixdat >> 4) & 0x03
        thread = frame_threads.get(thread_no)
        return (thread[0] if thread is not None else None), offset
    method = (fixdat >> 4) & 0x07
    if method <= 2:
        _index, offset = _read_omf_index(payload, offset)
    return method, offset


def _consume_fixupp_target(
    payload: bytes,
    offset: int,
    fixdat: int,
    target_threads: dict[int, tuple[int, int]],
) -> tuple[int | None, int, int]:
    if fixdat & 0x08:
        thread_no = fixdat & 0x03
        thread = target_threads.get(thread_no)
        if thread is None:
            return None, 0, offset
        return thread[0], thread[1], offset
    method = fixdat & 0x03
    index, offset = _read_omf_index(payload, offset)
    return method, index, offset


def _read_omf_numeric_value(payload: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(payload):
        return 0, offset
    code = payload[offset]
    offset += 1
    if code <= 0x80:
        return code, offset
    sizes = {0x81: 2, 0x84: 3, 0x88: 4}
    size = sizes.get(code, 0)
    if size <= 0 or offset + size > len(payload):
        return 0, len(payload)
    value = int.from_bytes(payload[offset : offset + size], "little")
    return value, offset + size


def _dedupe_referenced_names(referenced_names: tuple[PatPublicName, ...]) -> tuple[PatPublicName, ...]:
    seen: set[tuple[int, str]] = set()
    unique: list[PatPublicName] = []
    for ref in sorted(referenced_names, key=lambda item: (item.offset, item.name)):
        key = (ref.offset, ref.name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ref)
    return tuple(unique)


def _read_omf_index(payload: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(payload):
        return 0, offset
    first = payload[offset]
    if first & 0x80:
        if offset + 1 >= len(payload):
            return first & 0x7F, len(payload)
        return ((first & 0x7F) << 8) | payload[offset + 1], offset + 2
    return first, offset + 1


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def _segment_looks_like_code(segment: _OMFSegment) -> bool:
    text = f"{segment.name} {segment.class_name}".upper()
    if any(token in text for token in ("CODE", "TEXT")):
        return True
    if any(token in text for token in ("DATA", "BSS", "STACK")):
        return False
    return bool(segment.max_written_end)


def _run_local_plb(input_path: Path, out_path: Path, *, flair_root: Path | None = None) -> bool:
    root = flair_root or Path("/home/xor/ida77/flair77")
    plb_path = root / "bin" / "linux" / "plb"
    if not plb_path.exists():
        return False
    with tempfile.NamedTemporaryFile(prefix="inertia-plb-", suffix=".pat", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [str(plb_path), str(input_path), str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return False
        modules = parse_pat_file(tmp_path)
        if not modules:
            return False
        out_path.write_text(tmp_path.read_text(errors="ignore"))
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def _discover_candidate_pat_inputs(binary_path: Path) -> list[Path]:
    parent = binary_path.parent
    candidates: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_file():
            continue
        if child == binary_path:
            continue
        if child.suffix.lower() in {".pat", ".obj", ".lib"}:
            candidates.append(child)
    return candidates


def _pick_pat_cache_dir(binary_path: Path) -> Path:
    preferred = binary_path.parent / ".inertia_pat_cache"
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


def _load_project_image(project) -> tuple[int, bytes] | None:
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    memory = getattr(getattr(project, "loader", None), "memory", None)
    if main_object is None or memory is None:
        return None
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return None
    size = max_addr - min_addr + 1
    try:
        return min_addr, bytes(memory.load(min_addr, size))
    except Exception:
        return None


def _find_pat_matches(
    image_bytes: bytes,
    module: PatModule | CachedPatRegexSpec,
    *,
    backend: str | None = None,
) -> list[int]:
    selected_backend = _normalize_pat_backend_choice(backend)
    module_length = module.module_length
    if module_length <= 0 or module_length > len(image_bytes):
        return []
    checked_match_length = _get_pat_checked_match_length(module)
    if selected_backend == "hyperscan":
        hits = _find_pat_matches_hyperscan(image_bytes, module, checked_match_length)
        return hits if hits is not None else []
    hits: list[int] = []
    end_limit = len(image_bytes) - module_length + 1
    regex = _get_pat_module_regex(module)
    for match in regex.finditer(image_bytes):
        start = match.start()
        if start >= end_limit:
            continue
        hits.append(start)
        if len(hits) > 4:
            break
    return hits


def _find_pat_matches_hyperscan(
    image_bytes: bytes,
    module: PatModule | CachedPatRegexSpec,
    checked_match_length: int,
) -> list[int] | None:
    if _hyperscan is None or checked_match_length <= 0:
        return None
    try:
        db = _get_pat_module_hyperscan_db(module)
    except Exception:
        return None
    hits: list[int] = []
    end_limit = len(image_bytes) - module.module_length + 1

    def _on_match(_expr_id, _from_offset, end_offset, _flags, _context):
        start = end_offset - checked_match_length
        if 0 <= start < end_limit:
            hits.append(start)
        return len(hits) > 4

    try:
        db.scan(image_bytes, _on_match)
    except Exception:
        return None
    return hits


def _normalize_pat_backend_choice(backend: str | None) -> str:
    choice = (backend or _default_pat_backend()).strip().lower()
    if choice not in {"python_regex", "hyperscan"}:
        raise ValueError(f"Unsupported PAT backend: {backend!r}")
    if choice == "hyperscan" and _hyperscan is None:
        raise RuntimeError("PAT backend 'hyperscan' requested but the hyperscan module is not installed.")
    return choice


def _default_pat_backend() -> str:
    return "hyperscan" if _hyperscan is not None else "python_regex"


@lru_cache(maxsize=16)
def load_cached_pat_regex_specs(pat_path: Path, cache_dir: Path) -> tuple[CachedPatRegexSpec, ...]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = _cache_key_for_file(pat_path)
    cache_path = cache_dir / f"{_sanitize_component(pat_path.stem)}-{cache_key}.patrx.pickle"
    try:
        cached = pickle.loads(cache_path.read_bytes())
        if isinstance(cached, tuple) and all(isinstance(item, CachedPatRegexSpec) for item in cached):
            return cached
    except Exception:
        pass
    modules = parse_pat_file(pat_path)
    specs = tuple(_compile_pat_module_to_cached_regex(module) for module in modules)
    try:
        cache_path.write_bytes(pickle.dumps(specs, protocol=pickle.HIGHEST_PROTOCOL))
    except OSError:
        pass
    return specs


def _compile_pat_module_to_cached_regex(module: PatModule) -> CachedPatRegexSpec:
    regex_source, scan_source, checked_match_length = _build_pat_regex_source(module)
    return CachedPatRegexSpec(
        source_path=module.source_path,
        compiler_name=module.compiler_name,
        module_name=module.module_name,
        regex_source=regex_source,
        scan_source=scan_source,
        checked_match_length=checked_match_length,
        module_length=module.module_length,
        public_names=module.public_names,
        referenced_names=module.referenced_names,
    )


def _get_pat_module_regex(module: PatModule | CachedPatRegexSpec):
    if isinstance(module, CachedPatRegexSpec):
        return _compile_regex_bytes(module.regex_source)
    regex_source, _scan_source, _checked_match_length = _build_pat_regex_source(module)
    return _compile_regex_bytes(regex_source)


@lru_cache(maxsize=4096)
def _build_pat_regex_source(module: PatModule) -> tuple[bytes, bytes, int]:
    checked_prefix_len = min(module.module_length, 32)
    python_parts = [_pattern_bytes_to_regex(module.pattern_bytes[:checked_prefix_len])]
    hyperscan_parts = [_pattern_bytes_to_hyperscan_regex(module.pattern_bytes[:checked_prefix_len])]
    if module.module_length > 32 and module.tail_bytes:
        python_parts.append(_pattern_bytes_to_regex(module.tail_bytes))
        hyperscan_parts.append(_pattern_bytes_to_hyperscan_regex(module.tail_bytes))
    scan_source = b"".join(hyperscan_parts)
    checked_match_length = checked_prefix_len + (len(module.tail_bytes) if module.module_length > 32 and module.tail_bytes else 0)
    return b"(?=(" + b"".join(python_parts) + b"))", scan_source, checked_match_length


def _pattern_bytes_to_regex(pattern: tuple[int | None, ...]) -> bytes:
    chunks: list[bytes] = []
    for byte in pattern:
        if byte is None:
            chunks.append(b".")
        else:
            chunks.append(re.escape(bytes([byte])))
    return b"".join(chunks)


def _pattern_bytes_to_hyperscan_regex(pattern: tuple[int | None, ...]) -> bytes:
    chunks: list[bytes] = []
    for byte in pattern:
        if byte is None:
            chunks.append(b".")
        else:
            chunks.append(f"\\x{byte:02x}".encode("ascii"))
    return b"".join(chunks)


@lru_cache(maxsize=4096)
def _compile_regex_bytes(regex_source: bytes):
    return re.compile(regex_source, re.DOTALL)


def _get_pat_checked_match_length(module: PatModule | CachedPatRegexSpec) -> int:
    if isinstance(module, CachedPatRegexSpec):
        return module.checked_match_length
    _regex_source, _scan_source, checked_match_length = _build_pat_regex_source(module)
    return checked_match_length


@lru_cache(maxsize=4096)
def _get_pat_module_hyperscan_db(module: PatModule | CachedPatRegexSpec):
    if _hyperscan is None:
        raise RuntimeError("hyperscan unavailable")
    if isinstance(module, CachedPatRegexSpec):
        scan_source = module.scan_source
    else:
        _regex_source, scan_source, _checked_match_length = _build_pat_regex_source(module)
    return _compile_hyperscan_database(scan_source)


@lru_cache(maxsize=4096)
def _compile_hyperscan_database(regex_source: bytes):
    if _hyperscan is None:
        raise RuntimeError("hyperscan unavailable")
    db = _hyperscan.Database(mode=_hyperscan.HS_MODE_BLOCK)
    db.compile(
        expressions=[regex_source.decode("latin1")],
        ids=[0],
        elements=1,
        flags=[_hyperscan.HS_FLAG_DOTALL | _hyperscan.HS_FLAG_SINGLEMATCH],
    )
    return db


def _bytes_match_pattern(image_bytes: bytes, start: int, pattern: tuple[int | None, ...], limit: int) -> bool:
    if start < 0 or start + limit > len(image_bytes):
        return False
    for index in range(limit):
        expected = pattern[index]
        if expected is None:
            continue
        if image_bytes[start + index] != expected:
            return False
    return True


def _decode_pat_bytes(text: str) -> list[int | None]:
    decoded: list[int | None] = []
    for idx in range(0, len(text), 2):
        token = text[idx : idx + 2]
        decoded.append(None if token == ".." else int(token, 16))
    return decoded


def _encode_pat_bytes(data: bytes | bytearray | list[int | None]) -> str:
    parts: list[str] = []
    for byte in data:
        parts.append(".." if byte is None else f"{byte:02X}")
    return "".join(parts)


def _sanitize_component(text: str) -> str:
    return _SAFE_NAME_RE.sub("-", text).strip("-") or "pat"


def _sanitize_pat_comment(text: str) -> str:
    return " ".join(text.replace("\n", " ").replace("\r", " ").split())


def _cache_key_for_file(path: Path) -> str:
    stat = path.stat()
    raw = f"{path}:{stat.st_mtime_ns}:{stat.st_size}:{_omf_pat_tool_cache_fingerprint()}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]


@lru_cache(maxsize=1)
def _omf_pat_tool_cache_fingerprint() -> str:
    try:
        tool_path = Path(__file__).resolve()
        stat = tool_path.stat()
        return f"{tool_path}:{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        return "omf_pat_tool_unknown"
