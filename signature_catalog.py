from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from inertia_decompiler.cache import (
    _cache_file_fingerprint,
    _cache_source_digest,
    _load_cache_json,
    _store_cache_json,
)
from inertia_decompiler.signature_matching_policy import signature_matching_disabled
from omf_pat import (
    LocalPatMatchResult,
    PatModule,
    PatPublicName,
    ensure_pat_from_omf_input,
    format_pat_module_line,
    load_cached_pat_regex_specs,
    match_pat_modules,
    normalized_pat_merge_name,
    parse_pat_file,
)

_SIGNATURE_MATCH_CACHE_COMPONENTS = (
    Path(__file__).resolve(),
    Path(__file__).resolve().parent / "omf_pat.py",
)


@dataclass(frozen=True)
class SignatureCatalogBuildResult:
    output_path: Path
    input_count: int
    imported_module_count: int
    unique_module_count: int
    duplicate_module_count: int
    source_paths: tuple[Path, ...]


def discover_signature_inputs(
    roots: list[Path] | tuple[Path, ...],
    *,
    recursive: bool = True,
) -> tuple[Path, ...]:
    inputs: list[Path] = []
    seen: set[Path] = set()
    suffixes = {".pat", ".obj", ".lib"}
    for root in roots:
        root = root.resolve()
        if root.is_file():
            if root.suffix.lower() in suffixes and root not in seen:
                seen.add(root)
                inputs.append(root)
            continue
        if not root.is_dir():
            continue
        iterator = root.rglob("*") if recursive else root.glob("*")
        for candidate in sorted(iterator):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in suffixes:
                continue
            if any(part in {".inertia_pat_cache", "__pycache__"} for part in candidate.parts):
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            inputs.append(resolved)
    return tuple(inputs)


def build_signature_catalog(
    roots: list[Path] | tuple[Path, ...],
    output_path: Path,
    *,
    recursive: bool = True,
    flair_root: Path | None = None,
    cache_dir: Path | None = None,
) -> SignatureCatalogBuildResult:
    discovered = discover_signature_inputs(roots, recursive=recursive)
    resolved_output = output_path.resolve()
    selected_inputs = tuple(path for path in discovered if path.resolve() != resolved_output)
    effective_cache_dir = cache_dir or (resolved_output.parent / ".signature_catalog_cache")
    effective_cache_dir.mkdir(parents=True, exist_ok=True)

    unique_modules: dict[tuple[object, ...], PatModule] = {}
    imported_module_count = 0
    duplicate_module_count = 0
    for input_path in selected_inputs:
        pat_path = ensure_pat_from_omf_input(input_path, effective_cache_dir, flair_root=flair_root)
        if pat_path is None:
            continue
        for module in parse_pat_file(pat_path):
            imported_module_count += 1
            key = (
                module.pattern_bytes,
                module.module_length,
                _normalized_pat_name_key(module.public_names),
                _normalized_pat_name_key(module.referenced_names),
                module.tail_bytes,
            )
            if key in unique_modules:
                duplicate_module_count += 1
                unique_modules[key] = _merge_pat_module_provenance(unique_modules[key], module)
                continue
            unique_modules[key] = module

    ordered_modules = sorted(
        unique_modules.values(),
        key=lambda module: (
            module.module_name.lower(),
            module.module_length,
            tuple((public.offset, public.name) for public in module.public_names),
            tuple((ref.offset, ref.name) for ref in module.referenced_names),
            tuple(-1 if byte is None else byte for byte in module.tail_bytes),
        ),
    )
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_text("".join(f"{format_pat_module_line(module)}\n" for module in ordered_modules) + "---\n")
    return SignatureCatalogBuildResult(
        output_path=resolved_output,
        input_count=len(selected_inputs),
        imported_module_count=imported_module_count,
        unique_module_count=len(ordered_modules),
        duplicate_module_count=duplicate_module_count,
        source_paths=selected_inputs,
    )


def _merge_pat_module_provenance(existing: PatModule, incoming: PatModule) -> PatModule:
    source_paths = _merge_provenance_values(existing.source_path, incoming.source_path)
    compiler_names = _merge_provenance_values(existing.compiler_name, incoming.compiler_name)
    return PatModule(
        source_path=source_paths,
        compiler_name=compiler_names,
        module_name=existing.module_name,
        pattern_bytes=existing.pattern_bytes,
        module_length=existing.module_length,
        public_names=existing.public_names,
        referenced_names=existing.referenced_names,
        tail_bytes=existing.tail_bytes,
    )


def _normalized_pat_name_key(names: tuple[PatPublicName, ...]) -> tuple[tuple[int, str], ...]:
    return tuple((entry.offset, normalized_pat_merge_name(entry.name)) for entry in names)


def _merge_provenance_values(left: str, right: str) -> str:
    values: list[str] = []
    for raw in (left, right):
        for value in (part.strip() for part in raw.split(" || ") if part.strip()):
            if value not in values:
                values.append(value)
    return " || ".join(values)


def match_signature_catalog(
    catalog_path: Path,
    binary_path: Path,
    project,
    *,
    backend: str | None = None,
    cache_dir: Path | None = None,
    compiler_names: tuple[str, ...] = (),
) -> LocalPatMatchResult:
    if signature_matching_disabled():
        return LocalPatMatchResult({}, {}, ())
    if not catalog_path.exists():
        return LocalPatMatchResult({}, {}, ())
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    memory = getattr(getattr(project, "loader", None), "memory", None)
    if main_object is None or memory is None:
        return LocalPatMatchResult({}, {}, ())
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return LocalPatMatchResult({}, {}, ())
    size = max_addr - min_addr + 1
    try:
        image_bytes = bytes(memory.load(min_addr, size))
    except Exception:
        return LocalPatMatchResult({}, {}, ())
    cache_key = _signature_catalog_match_cache_key(
        catalog_path=catalog_path,
        binary_path=binary_path,
        backend=backend,
        compiler_names=compiler_names,
    )
    if cache_key is not None:
        cached = _load_cache_json("signature_catalog_match", cache_key)
        cached_result = _decode_signature_catalog_match(cached)
        if cached_result is not None:
            return cached_result

    effective_cache_dir = cache_dir or (binary_path.parent / ".inertia_pat_cache")
    specs = load_cached_pat_regex_specs(catalog_path, effective_cache_dir)
    if not specs:
        return LocalPatMatchResult({}, {}, ())
    filtered_specs = _filter_specs_by_compiler_names(specs, compiler_names)
    if filtered_specs:
        specs = filtered_specs
    code_labels, code_ranges, matched_compiler_names = match_pat_modules(
        image_bytes,
        min_addr,
        specs,
        backend=backend,
    )
    source_formats = ("signature_catalog",) if code_labels or code_ranges else ()
    result = LocalPatMatchResult(code_labels, code_ranges, source_formats, matched_compiler_names)
    if cache_key is not None:
        _store_cache_json("signature_catalog_match", cache_key, _encode_signature_catalog_match(result))
    return result


def _signature_catalog_match_cache_key(
    *,
    catalog_path: Path,
    binary_path: Path,
    backend: str | None,
    compiler_names: tuple[str, ...],
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    catalog_fingerprint = _cache_file_fingerprint(catalog_path)
    if binary_fingerprint is None or catalog_fingerprint is None:
        return None
    return {
        "schema": 1,
        "kind": "signature_catalog_match",
        "binary": binary_fingerprint,
        "catalog": catalog_fingerprint,
        "backend": (backend or "").strip().lower(),
        "compiler_names": tuple(compiler_names),
        "components": _cache_source_digest(_SIGNATURE_MATCH_CACHE_COMPONENTS),
    }


def _encode_signature_catalog_match(result: LocalPatMatchResult) -> dict[str, object]:
    return {
        "code_labels": {str(addr): name for addr, name in result.code_labels.items()},
        "code_ranges": {str(addr): [span[0], span[1]] for addr, span in result.code_ranges.items()},
        "source_formats": list(result.source_formats),
        "matched_compiler_names": list(result.matched_compiler_names),
    }


def _decode_signature_catalog_match(payload: dict[str, object] | None) -> LocalPatMatchResult | None:
    if not isinstance(payload, dict):
        return None
    raw_labels = payload.get("code_labels")
    raw_ranges = payload.get("code_ranges")
    if not isinstance(raw_labels, dict) or not isinstance(raw_ranges, dict):
        return None
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    try:
        for addr_text, name in raw_labels.items():
            if not isinstance(name, str):
                return None
            code_labels[int(addr_text)] = name
        for addr_text, span in raw_ranges.items():
            if not (isinstance(span, list) and len(span) == 2 and all(isinstance(value, int) for value in span)):
                return None
            code_ranges[int(addr_text)] = (span[0], span[1])
    except (TypeError, ValueError):
        return None
    raw_formats = payload.get("source_formats", ())
    raw_compilers = payload.get("matched_compiler_names", ())
    source_formats = tuple(value for value in raw_formats if isinstance(value, str))
    matched_compiler_names = tuple(value for value in raw_compilers if isinstance(value, str))
    return LocalPatMatchResult(code_labels, code_ranges, source_formats, matched_compiler_names)


def _filter_specs_by_compiler_names(
    specs: tuple[CachedPatRegexSpec, ...],
    compiler_names: tuple[str, ...],
) -> tuple[CachedPatRegexSpec, ...]:
    ignored_filters = {"ida flair", "flair", "unknown"}
    normalized_filters = tuple(
        name.strip().lower()
        for name in compiler_names
        if name and name.strip() and name.strip().lower() not in ignored_filters
    )
    if not normalized_filters:
        return ()
    filtered: list[CachedPatRegexSpec] = []
    for spec in specs:
        compiler_name = getattr(spec, "compiler_name", "").strip().lower()
        if not compiler_name:
            continue
        if any(
            compiler_filter in compiler_name or compiler_name in compiler_filter
            for compiler_filter in normalized_filters
        ):
            filtered.append(spec)
    return tuple(filtered)
