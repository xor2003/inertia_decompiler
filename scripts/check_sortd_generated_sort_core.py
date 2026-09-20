#!/usr/bin/env python3
"""Compile and execute the sidecar-free generated SORTD sort core.

Layer: Tooling/gates.
Responsibility: keep generated function bodies unchanged while adapting binary
storage addresses to a host test image and checking source-derived outcomes.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.generated_c_function_extraction import (  # noqa: E402
    generated_function_definition_span,
    load_generated_function_artifacts,
)
from scripts.sortd_gp_runtime import (  # noqa: E402
    DEFAULT_GP_RUNTIME_ABI_8616,
    GPRegisterRuntimeABI8616,
    prepare_sortd_gp_runtime,
)

DEFAULT_TRANSCRIPT: Path = REPO_ROOT / "angr_platforms/.cache/test_pipeline/sortd_sidecar_free.txt"
DEFAULT_BUILD_DIR: Path = REPO_ROOT / "angr_platforms/.cache/test_pipeline/sortd_generated_sort_core"
DEFAULT_HARNESS: Path = REPO_ROOT / "angr_platforms/tests/fixtures/sortd_generated_sort_core_harness.c"
SORT_FUNCTIONS: tuple[int, ...] = (
    0x10060, 0x101F0, 0x102E0, 0x10498,
    0x10560, 0x10678, 0x106C8, 0x10768,
    0x107B8, 0x10808, 0x108D0, 0x10970,
    0x109E8, 0x10A88, 0x10B50, 0x10C18,
    0x10CE0, 0x10E70, 0x10F38,
)
_FUNCTION_MARKER_RE = re.compile(
    r"(?m)^/\* == function (?P<addr>0x[0-9a-f]+) (?P<name>[A-Za-z_][A-Za-z0-9_]*) == \*/",
    re.IGNORECASE,
)
_FUNCTION_RESULT_RE = re.compile(
    r"(?m)^(?:\[[^\n]*\][ \t]+)?/\* info: function 0x[0-9a-f]+ "
    r"[A-Za-z_][A-Za-z0-9_]* attempt=[a-z_]+ validation=[a-z_]+ \*/[ \t]*$",
    re.IGNORECASE,
)
_GLOBAL_ARRAY_RE = re.compile(
    r"(?m)^[ \t]*extern[ \t]+(?P<type>[A-Za-z_][A-Za-z0-9_ ]*?)"
    r"[ \t]+(?P<name>g_(?P<offset>[0-9A-Fa-f]{4,5}))"
    r"\[(?P<count>[0-9]*)\];[ \t]*$"
)
_GLOBAL_SCALAR_RE = re.compile(
    r"(?m)^[ \t]*extern[ \t]+(?P<type>[A-Za-z_][A-Za-z0-9_ ]*?)"
    r"[ \t]+(?P<name>g_(?P<offset>[0-9A-Fa-f]{4,5}));[ \t]*$"
)
_DOS_DEFS_TO_DROP: tuple[str, ...] = (
    "typedef signed char int8_t;",
    "typedef signed short int16_t;",
    "typedef signed long int32_t;",
    "typedef unsigned char uint8_t;",
    "typedef unsigned short uint16_t;",
    "typedef unsigned long uint32_t;",
    "typedef long clock_t;",
    "typedef long time_t;",
    "clock_t clock(void);",
    "int rand(void);",
    "void srand(unsigned int seed);",
    "time_t time(time_t *out);",
    "long aNldiv(long dividend, long divisor);",
)


def _sanitize_generated_source(source: str) -> str:
    """Remove DOS.C-compatible declarations that are unnecessary in hosted builds."""
    sanitized: list[str] = []
    for line in source.splitlines():
        text = line.strip()
        if not text:
            continue
        if text == "#include <DOS.H>":
            continue
        canonical = " ".join(text.split())
        if canonical in _DOS_DEFS_TO_DROP:
            continue
        sanitized.append(line)
    return "\n".join(sanitized) + "\n"


@dataclass(frozen=True, slots=True)
class GeneratedFunction:
    """One generated function and its local declaration prelude."""

    address: int
    name: str
    source: str


def _function_name_from_address(address: int) -> str:
    """Return decompiler naming convention for a function address."""
    return f"sub_{address:04x}"


def _definition_end(source: str, function_name: str) -> int:
    """Return the end offset of one generated C function definition."""
    return int(generated_function_definition_span(source, function_name)[1])


def _last_definition_span(source: str, function_name: str) -> tuple[int, int]:
    """Return the last balanced definition, after parallel-worker diagnostics."""
    latest: tuple[int, int] | None = None
    cursor = 0
    while cursor < len(source):
        try:
            start, end = generated_function_definition_span(source[cursor:], function_name)
        except ValueError:
            break
        latest = (cursor + start, cursor + end)
        cursor += end
    if latest is None:
        raise ValueError(f"missing generated definition for {function_name}")
    return latest


def _extract_generated_functions_plain(transcript: str) -> dict[int, GeneratedFunction]:
    """Extract functions from transcripts without the legacy function markers."""
    spans: dict[int, tuple[int, int]] = {}
    for address in SORT_FUNCTIONS:
        try:
            spans[address] = _last_definition_span(
                transcript,
                _function_name_from_address(address),
            )
        except ValueError:
            continue
    if not spans:
        return {}
    first_definition = min(start for start, _end in spans.values())
    function_results = tuple(_FUNCTION_RESULT_RE.finditer(transcript, 0, first_definition))
    if function_results:
        declaration_start = transcript.find("\n", function_results[-1].end()) + 1
    else:
        declaration_start = max(0, transcript.rfind("#include", 0, first_definition))
    prelude = transcript[declaration_start:first_definition]
    functions: dict[int, GeneratedFunction] = {}
    for address, (start, end) in spans.items():
        name = _function_name_from_address(address)
        generated = f"{prelude}{transcript[start:end]}".strip() + "\n"
        functions[address] = GeneratedFunction(address, name, generated)
    return functions


def extract_generated_functions(transcript: str) -> dict[int, GeneratedFunction]:
    """Extract generated C blocks by exact function address."""
    markers = tuple(_FUNCTION_MARKER_RE.finditer(transcript))
    if not markers:
        return _extract_generated_functions_plain(transcript)
    functions: dict[int, GeneratedFunction] = {}
    for marker_index, marker in enumerate(markers):
        address = int(marker.group("addr"), 16)
        if address not in SORT_FUNCTIONS:
            continue
        block_end = (
            markers[marker_index + 1].start()
            if marker_index + 1 < len(markers)
            else len(transcript)
        )
        block = transcript[marker.end() : block_end]
        c_marker = block.find("/* -- c -- */")
        if c_marker < 0:
            continue
        generated = block[c_marker + len("/* -- c -- */") :]
        name = _function_name_from_address(address)
        generated = generated[: _definition_end(generated, name)].strip() + "\n"
        functions[address] = GeneratedFunction(address, name, generated)
    # When a full transcript includes the c marker but misses a function marker,
    # fallback to plain signature extraction.
    if not functions:
        return _extract_generated_functions_plain(transcript)
    return functions


def _map_binary_globals(source: str) -> str:
    """Replace extern globals with typed views into one binary DS image."""

    def replace_array(match: re.Match[str]) -> str:
        value_type = " ".join(match.group("type").split())
        value_type = {"long": "inertia_i32", "unsigned long": "inertia_u32"}.get(value_type, value_type)
        offset = int(match.group("offset"), 16)
        return (
            f"#define {match.group('name')} "
            f"(({value_type} *)(inertia_memory + 0x{offset:04X}u))"
        )

    def replace_scalar(match: re.Match[str]) -> str:
        value_type = " ".join(match.group("type").split())
        value_type = {"long": "inertia_i32", "unsigned long": "inertia_u32"}.get(value_type, value_type)
        offset = int(match.group("offset"), 16)
        return (
            f"#define {match.group('name')} "
            f"(*({value_type} *)(inertia_memory + 0x{offset:04X}u))"
        )

    return _GLOBAL_SCALAR_RE.sub(
        replace_scalar,
        _GLOBAL_ARRAY_RE.sub(replace_array, source),
    )


def _runtime_header() -> str:
    """Return the portable-flat runtime declarations used by generated units."""
    return """#include <stdbool.h>
#include <stdint.h>

typedef int32_t inertia_i32 __attribute__((aligned(1)));
typedef uint32_t inertia_u32 __attribute__((aligned(1)));

extern uint8_t inertia_memory[];
extern uint16_t inertia_cs;
extern uint16_t inertia_ds;
extern uint16_t inertia_es;
extern uint16_t inertia_ss;
// Normalize legacy 16-bit qualifier keywords in decompiler transcripts.
#define far

#define SEG_LINEAR(seg, off) ((((uint32_t)(seg)) << 4) + ((uint16_t)(off)))
#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_PTR(seg, off)    (&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U8(seg, off)     (*(uint8_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U32(seg, off)    (*(inertia_u32 *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define MEM_U8(ptr)          (*(uint8_t *)(ptr))
#define MEM_U16(ptr)         (*(uint16_t *)(ptr))
#define MEM_U32(ptr)         (*(inertia_u32 *)(ptr))
"""


def build_and_run(
    transcript_path: Path,
    build_dir: Path,
    *,
    compiler: str,
    harness_path: Path,
    function_c_dir: Path | None = None,
    gp_runtime_abi: GPRegisterRuntimeABI8616 = DEFAULT_GP_RUNTIME_ABI_8616,
) -> subprocess.CompletedProcess[str]:
    """Build generated sort functions and execute the source-derived harness."""
    if function_c_dir is None:
        functions = extract_generated_functions(
            transcript_path.read_text(encoding="utf-8", errors="replace")
        )
    else:
        artifacts = load_generated_function_artifacts(function_c_dir, SORT_FUNCTIONS)
        functions = {
            address: GeneratedFunction(address, _function_name_from_address(address), source)
            for address, source in artifacts.items()
        }
    missing = tuple(address for address in SORT_FUNCTIONS if address not in functions)
    if missing:
        formatted = ", ".join(f"{address:#x}" for address in missing)
        raise ValueError(f"transcript is missing generated sort functions: {formatted}")

    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    sources: list[Path] = []
    for address in SORT_FUNCTIONS:
        function = functions[address]
        path = build_dir / f"{function.name}.c"
        path.write_text(
            _runtime_header() + "\n" + _sanitize_generated_source(_map_binary_globals(function.source)),
            encoding="utf-8",
        )
        sources.append(path)
    harness = build_dir / "harness.c"
    shutil.copyfile(harness_path, harness)
    sources.append(harness)
    runtime, runtime_flags = prepare_sortd_gp_runtime(
        build_dir, harness_path.with_name("sortd_generated_behavior_runtime.c"), gp_runtime_abi,
    )
    sources.append(runtime)

    executable = build_dir / "sortd_generated_sort_core"
    compile_process = subprocess.run(
        [
            compiler,
            "-std=c11",
            "-O0",
            "-Wall",
            "-Wextra",
            "-Werror=implicit-function-declaration",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            *runtime_flags,
            *(str(path) for path in sources),
            "-o",
            str(executable),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if compile_process.returncode != 0:
        return compile_process
    return subprocess.run(
        [str(executable)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def main() -> int:
    """Run the generated sort-core compile and behavior gate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transcript", type=Path, default=DEFAULT_TRANSCRIPT)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS)
    parser.add_argument("--function-c-dir", type=Path)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--gp-runtime-abi", type=GPRegisterRuntimeABI8616,
                        choices=list(GPRegisterRuntimeABI8616), default=DEFAULT_GP_RUNTIME_ABI_8616)
    args = parser.parse_args()

    try:
        result = build_and_run(
            args.transcript,
            args.build_dir,
            compiler=args.compiler,
            harness_path=args.harness,
            function_c_dir=args.function_c_dir,
            gp_runtime_abi=args.gp_runtime_abi,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"[sortd-generated-sort-core] failed error={error}")
        return 1
    if result.returncode != 0:
        print(
            "[sortd-generated-sort-core] failed "
            f"exit={result.returncode}\n{result.stdout}{result.stderr}"
        )
        return 1
    print(
        "[sortd-generated-sort-core] "
        f"functions={len(SORT_FUNCTIONS)} compile=passed behavior=passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
