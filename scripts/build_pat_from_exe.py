#!/usr/bin/env python3
"""Generate PAT signatures using the decompiler's default function discovery path.

Layer: Tooling/gates
Responsibility: build PAT catalogs from linked DOS/16-bit executables with the same
angr function discovery used by the main decompiler pipeline.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

if TYPE_CHECKING:
    import angr

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import contextlib  # noqa: E402

import omf_pat  # noqa: E402 - repository root is bootstrapped above
from inertia_decompiler.cache import _cache_json_path, _recovery_cache_key  # noqa: E402
from inertia_decompiler.cli_function_discovery import (  # noqa: E402
    _recover_fast_exe_catalog,
    _recover_seeded_exe_functions,
)
from inertia_decompiler.project_loading import _build_project_cached  # noqa: E402
from inertia_decompiler.sidecar_metadata import _load_lst_metadata  # noqa: E402


def _parse_int(value: str) -> int:
    return int(value, 0)


def _default_base_and_entry(binary_path: Path) -> tuple[int, int, bool]:
    suffix = binary_path.suffix.lower()
    if suffix in {".bin", ".raw", ".cod", ".com"}:
        return 0x1000, 0x1000, suffix in {".bin", ".raw", ".cod", ".com"}
    return 0, 0, False


def _build_project(binary_path: Path) -> angr.Project:
    """Build the angr project using the decompiler's canonical loader."""
    base_addr, entry_point, force_blob = _default_base_and_entry(binary_path)
    return _build_project_cached(
        str(binary_path),
        force_blob=force_blob,
        base_addr=base_addr,
        entry_point=entry_point,
    )


def _clear_function_discovery_cache(project: angr.Project, binary_path: Path) -> None:
    """Remove the cached seeded-function catalog for one project image."""
    main_object = project.loader.main_object
    if main_object is None:
        linked_base = None
        max_addr = None
    else:
        linked_base = main_object.linked_base
        max_addr = main_object.max_addr

    key = _recovery_cache_key(
        binary_path=binary_path,
        kind="seeded_function_catalog",
        extra={
            "entry": project.entry,
            "linked_base": linked_base,
            "max_addr": max_addr,
        },
    )
    if key is None:
        return
    cache_path = _cache_json_path("recovery", key)
    with contextlib.suppress(OSError):
        cache_path.unlink()


def _estimate_function_sizes(
    functions: list[tuple[int, int]],
    *,
    image_end: int | None,
) -> list[tuple[int, int]]:
    if not functions:
        return []
    unique = _unique_functions(functions)
    if not unique:
        return []
    if image_end is None:
        image_end = unique[-1][0]

    resolved: list[tuple[int, int]] = []
    for index, (start, size) in enumerate(unique):
        if size <= 0:
            estimated = max(0, unique[index + 1][0] - start) if index + 1 < len(unique) else max(0, image_end - start)
            size = estimated
        resolved.append((start, max(0, int(size))))
    return resolved


def _discover_functions_from_lst_metadata(
    binary_path: Path,
    project: angr.Project,
) -> list[tuple[int, int]]:
    """Read function ranges from optional LST metadata."""
    metadata = _load_lst_metadata(
        binary_path,
        project,
        pat_backend=None,
        signature_catalog=None,
    )
    if metadata is None:
        return []
    code_ranges = metadata.code_ranges
    if not isinstance(code_ranges, dict):
        return []
    discovered: list[tuple[int, int]] = []
    for start, span in code_ranges.items():
        if not isinstance(start, int) or not isinstance(span, tuple) or len(span) != 2:
            continue
        end = int(span[1]) if len(span) > 1 else None
        if not isinstance(end, int) or end <= start:
            continue
        discovered.append((start, end - start))
    return discovered


def _discover_functions_with_seeded(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    max_functions: int | None,
) -> list[tuple[int, int]]:
    """Recover function ranges with the seeded 16-bit discovery path."""
    if project.arch.name != "86_16":
        return []
    limit = None if max_functions is None else max(0, max_functions) or None
    recovery_result = _recover_seeded_exe_functions(
        project,
        timeout=timeout,
        limit=limit,
        region_span=max(0x120, int(window)),
        per_function_timeout=1,
        return_addrs=False,
        include_library_functions=False,
    )
    pairs = recovery_result[0] if isinstance(recovery_result, tuple) else recovery_result
    discovered: list[tuple[int, int]] = []
    for _cfg, function in pairs:
        addr = function.addr
        size = function.size
        if not isinstance(addr, int) or not isinstance(size, int):
            continue
        discovered.append((addr, size))
    return discovered


def _image_end_addr(project: angr.Project) -> int | None:
    """Return the exclusive end address of the loaded main object."""
    main_object = project.loader.main_object
    if main_object is None:
        return None
    linked_base = main_object.linked_base
    max_addr = main_object.max_addr
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return None
    return linked_base + max_addr + 1


def _discover_functions_with_decompiler(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    binary_path: Path | None = None,
    max_functions: int | None,
    mode: str = "auto",
) -> list[tuple[int, int]]:
    """Discover function ranges through the requested decompiler evidence path."""
    if mode in {"auto", "sidecar", "lst"} and binary_path is not None:
        lst_functions = _discover_functions_from_lst_metadata(binary_path, project)
        if lst_functions:
            return lst_functions

    if mode in {"auto", "seeded"}:
        recovered = _discover_functions_with_seeded(project, timeout=timeout, window=window, max_functions=max_functions)
        if recovered:
            return recovered

    if project.arch.name != "86_16":
        raise RuntimeError("Pat builder in this mode currently supports 86_16 only.")

    limit = None if max_functions is None else max(0, max_functions) or None
    pairs = _recover_fast_exe_catalog(
        project,
        timeout=timeout,
        window=window,
        low_memory=False,
        limit=limit,
    )

    discovered: list[tuple[int, int]] = []
    for _cfg, function in pairs:
        addr = function.addr
        size = function.size
        if not isinstance(addr, int) or not isinstance(size, int):
            continue
        discovered.append((addr, size))
    return discovered


def _read_function_bytes(project: angr.Project, start: int, size: int) -> bytes:
    """Read one recovered function from the lifted block or loader memory."""
    size = max(0, int(size))
    if size <= 0:
        return b""
    try:
        block = project.factory.block(start, size=size, opt_level=0)
        if block.bytes is None:
            return b""
        bytes_data = bytes(block.bytes)
        if len(bytes_data) == size:
            return bytes_data
        if len(bytes_data) > size:
            return bytes_data[:size]
    except Exception:
        pass
    try:
        return bytes(project.loader.memory.load(start, size))
    except Exception:
        return b""


def _unique_functions(functions: list[tuple[int, int]]) -> list[tuple[int, int]]:
    unique: dict[int, int] = {}
    for start, size in functions:
        if start in unique and unique[start] >= size:
            continue
        unique[start] = size
    return sorted(unique.items())


def _wildcard_range_8616(wild: list[int | None], start: int, size: int) -> None:
    """Wildcard one byte range inside the function byte buffer."""
    for idx in range(start, start + size):
        if 0 <= idx < len(wild):
            wild[idx] = None


def _wildcard_immediate_8616(
    wild: list[int | None],
    operand: Any,  # noqa: ANN401 - dynamic Capstone operand boundary
    base: int,
    max_len: int,
) -> None:
    """Wildcard one instruction's immediate operand bytes."""
    imm_offset = int(getattr(operand, "imm_offset", 0) or 0)
    imm_size = int(getattr(operand, "size", 0) or 0)
    if imm_size > 0 and imm_offset + imm_size <= max_len - base:
        _wildcard_range_8616(wild, base + imm_offset, imm_size)


def _wildcard_memory_8616(
    wild: list[int | None],
    operand: Any,  # noqa: ANN401 - dynamic Capstone operand boundary
    base: int,
    max_len: int,
) -> None:
    """Wildcard one instruction's memory displacement bytes."""
    mem = getattr(operand, "mem", None)
    if mem is None:
        return
    disp = int(getattr(mem, "disp", 0))
    disp_size = 1
    if disp != 0:
        disp_size = 1 if -0x80 <= disp <= 0x7f else 2
    disp_offset = int(getattr(mem, "disp_offset", 0) or 0)
    if disp_size > 0 and disp_offset > 0 and disp_offset + disp_size <= max_len - base:
        _wildcard_range_8616(wild, base + disp_offset, disp_size)


def _wildcard_transfer_bytes_8616(
    wild: list[int | None],
    insn: Any,  # noqa: ANN401 - dynamic Capstone instruction boundary
    base: int,
) -> None:
    """Wildcard far transfer addresses and near/short jump offsets."""
    raw = bytes(insn.bytes)
    if raw and raw[0] in {0x9A, 0xEA} and len(raw) >= 5:
        _wildcard_range_8616(wild, base + 1, 4)
    if raw and raw[0] in {0xE8, 0xE9, 0xEB}:
        offset = 1 if raw[0] == 0xEB else 2
        _wildcard_range_8616(wild, base + 1, offset)




def _wildcard_inst_operands(function_bytes: bytes, function_start: int) -> list[int | None]:
    """Wildcard instruction operand bytes used by the PAT signature matcher.

    Dynamic boundary: Capstone's third-party Python instruction and operand
    proxies expose version-dependent optional attributes, so guarded access is
    required here.

    Keep layout-stable opcode bytes and wildcard:
    - immediate operands,
    - memory displacement bytes,
    - far transfer addresses.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    wild: list[int | None] = list(function_bytes)
    max_len = len(function_bytes)

    for insn in md.disasm(function_bytes, function_start):
        base = insn.address - function_start

        for operand in getattr(insn, "operands", ()) or ():
            if operand.type == X86_OP_IMM:
                _wildcard_immediate_8616(wild, operand, base, max_len)
            elif operand.type == X86_OP_MEM:
                _wildcard_memory_8616(wild, operand, base, max_len)

        _wildcard_transfer_bytes_8616(wild, insn, base)

    return wild


def generate_pat_from_exe(
    binary_path: Path,
    *,
    output_path: Path | None = None,
    timeout: int = 60,
    window: int = 0x200,
    max_functions: int | None = None,
    discovery_mode: str = "auto",
    project: angr.Project | None = None,
) -> tuple[Path, int]:
    """Generate a PAT file from functions recovered in an executable."""
    if project is None:
        project = _build_project(binary_path)
    project_functions = _discover_functions_with_decompiler(
        project,
        timeout=max(1, int(timeout)),
        window=max(0x120, int(window)),
        max_functions=max_functions,
        binary_path=binary_path,
        mode=discovery_mode,
    )

    functions = _estimate_function_sizes(
        project_functions,
        image_end=_image_end_addr(project),
    )

    lines: list[str] = []
    for start, size in functions:
        if size < 4:
            continue
        function_bytes = _read_function_bytes(project, start, size)
        if len(function_bytes) < 4:
            continue
        wildcarded = _wildcard_inst_operands(function_bytes, start)
        line = omf_pat._build_pat_line(
            wildcarded,
            public_name=f"fcn_{start:05x}",
            module_name=binary_path.name,
            referenced_names=(),
        )
        if line is not None:
            lines.append(line)

    if output_path is None:
        output_path = binary_path.with_suffix(".pat")
    output_path = output_path.resolve()
    output_path.write_text("".join(f"{line}\n" for line in lines) + "---\n")
    return output_path, len(lines)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build PAT from executable using decompiler discovery.")
    parser.add_argument("binary", type=Path, help="Input executable path.")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output .pat file path.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Discovery timeout in seconds. Defaults to 60.",
    )
    parser.add_argument(
        "--window",
        type=_parse_int,
        default=0x200,
        help="Bounded recovery window passed to decompiler discovery. Defaults to 0x200.",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Maximum number of functions to emit. Defaults to 0 (all).",
    )
    parser.add_argument(
        "--discovery-mode",
        choices=("auto", "sidecar", "seeded", "fast"),
        default="auto",
        help="Function discovery mode: sidecar (LST/IDA ranges), seeded (function recovery), fast (legacy quick), or auto.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore recovery cache for decompiler function discovery (slower, but fresh result).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the PAT builder command-line entrypoint."""
    args = _build_arg_parser().parse_args(argv)
    project = None
    if args.no_cache:
        project = _build_project(args.binary)
        _clear_function_discovery_cache(project, args.binary)
    max_functions = None if args.max_functions <= 0 else args.max_functions
    try:
        out_path, count = generate_pat_from_exe(
            args.binary,
            output_path=args.output,
            timeout=max(1, args.timeout),
            window=max(0x120, args.window),
            max_functions=max_functions,
            discovery_mode=args.discovery_mode,
            project=project,
        )
    except Exception as ex:
        print(f"failed to generate PAT: {ex}", file=sys.stderr)
        return 1
    print(f"output={out_path}")
    print(f"functions={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
