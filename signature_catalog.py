from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from omf_pat import (
    LocalPatMatchResult,
    PatModule,
    ensure_pat_from_omf_input,
    format_pat_module_line,
    load_cached_pat_regex_specs,
    match_pat_modules,
    parse_pat_file,
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
                module.public_names,
                module.referenced_names,
                module.tail_bytes,
            )
            if key in unique_modules:
                duplicate_module_count += 1
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


def match_signature_catalog(
    catalog_path: Path,
    binary_path: Path,
    project,
    *,
    backend: str | None = None,
    cache_dir: Path | None = None,
) -> LocalPatMatchResult:
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
    effective_cache_dir = cache_dir or (binary_path.parent / ".inertia_pat_cache")
    specs = load_cached_pat_regex_specs(catalog_path, effective_cache_dir)
    if not specs:
        return LocalPatMatchResult({}, {}, ())
    code_labels, code_ranges = match_pat_modules(image_bytes, min_addr, specs, backend=backend)
    source_formats = ("signature_catalog",) if code_labels or code_ranges else ()
    return LocalPatMatchResult(code_labels, code_ranges, source_formats)
