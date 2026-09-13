#!/usr/bin/env python3
"""Verify MS C example runtime gates against compiled fixture outputs.

Layer: Tooling/gates.
Responsibility: verify decompiled MS C examples by compiling and running focused harnesses.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_msc6_examples import (  # noqa: E402
    DEFAULT_KVIKDOS,
    DEFAULT_MSC6_ROOT,
    _compile_and_link,
    _run_example,
)
from scripts.msc6_runtime_support import msc6_runtime_state_declarations  # noqa: E402

DEFAULT_DECOMPILE = REPO_ROOT / "decompile.py"
DEFAULT_BUILD_DIR = REPO_ROOT / "examples" / "build_msc6"
DEFAULT_OUT_DIR = DEFAULT_BUILD_DIR / "runtime_gate"


class RuntimeGateStage(Enum):
    DECOMPILE = auto()
    EXTRACT = auto()
    COMPILE = auto()
    LINK = auto()
    RUN = auto()


@dataclass(frozen=True)
class FunctionSpec:
    name: str
    proc_kind: str | None = None
    addr: str | None = None


@dataclass(frozen=True)
class ExampleSpec:
    name: str
    exe: Path
    output_stem: str
    functions: tuple[FunctionSpec, ...]
    harness_main: str


CMP16_HARNESS_MAIN = """
int main(void)
{
    if (cmp_i16(-2, 5) != -1) {
        return 1;
    }
    if (cmp_i16(9, 3) != 1) {
        return 2;
    }
    if (cmp_i16(7, 7) != 0) {
        return 3;
    }
    if (rel_i16(-2, 5) != (1 | 2 | 32)) {
        return 4;
    }
    if (rel_i16(9, 3) != (4 | 8 | 32)) {
        return 5;
    }
    if (rel_i16(7, 7) != (2 | 8 | 16)) {
        return 6;
    }
    if (rel_u16(2U, 9U) != (1 | 2 | 32)) {
        return 7;
    }
    if (rel_u16(12U, 3U) != (4 | 8 | 32)) {
        return 8;
    }
    if (rel_u16(6U, 6U) != (2 | 8 | 16)) {
        return 9;
    }
    if (clamp_u16(10U, 7U) != 7U) {
        return 10;
    }
    if (clamp_u16(6U, 7U) != 6U) {
        return 11;
    }
    if (in_window_i16(4, 1, 7) != 1) {
        return 12;
    }
    if (in_window_i16(9, 1, 7) != 0) {
        return 13;
    }
    return 255;
}
"""


CMP32_HARNESS_MAIN = """
int main(void)
{
    long a;
    long b;
    unsigned long ua;
    unsigned long ub;
    long clipped;

    a = 100000L;
    b = -2000L;
    ua = 300000UL;
    ub = 300001UL;
    clipped = clamp_window(a, -100L, 50000L);
    if (select_max(a, b) != a) {
        return 1;
    }
    if (compare_signed(a, b) != 1) {
        return 2;
    }
    if (compare_signed(b, a) != -1) {
        return 3;
    }
    if (compare_signed(a, a) != 0) {
        return 4;
    }
    if (compare_unsigned(ua, ub) != -1) {
        return 5;
    }
    if (compare_unsigned(ub, ua) != 1) {
        return 6;
    }
    if (compare_unsigned(ua, ua) != 0) {
        return 7;
    }
    if (rel_signed32(b, a) != (1 | 2 | 32)) {
        return 8;
    }
    if (rel_signed32(a, b) != (4 | 8 | 32)) {
        return 9;
    }
    if (rel_signed32(a, a) != (2 | 8 | 16)) {
        return 10;
    }
    if (rel_unsigned32(ua, ub) != (1 | 2 | 32)) {
        return 11;
    }
    if (rel_unsigned32(ub, ua) != (4 | 8 | 32)) {
        return 12;
    }
    if (rel_unsigned32(ua, ua) != (2 | 8 | 16)) {
        return 13;
    }
    if (clipped != 50000L) {
        return 14;
    }
    return 255;
}
"""


FPTR_HARNESS_MAIN = """
int main(void)
{
    if (apply_twice(inc_one, 5) != 7) {
        return 1;
    }
    if (apply_twice(dec_one, 8) != 6) {
        return 2;
    }
    if (select_and_apply(1, 5) != 7) {
        return 3;
    }
    if (select_and_apply(0, 8) != 6) {
        return 4;
    }
    return 255;
}
"""

SIMPLE_CONTROL_HARNESS_MAIN = """
int main(void)
{
    int a;
    int b;
    int c;

    a = classify(7);
    b = sum_to(6);
    c = switch_fold(2);
    if (classify(-4) != -1) {
        return 1;
    }
    if (classify(0) != 0) {
        return 2;
    }
    if (a != 1) {
        return 3;
    }
    if (b != 3) {
        return 4;
    }
    if (c != 22) {
        return 5;
    }
    return 255;
}
"""

LOOPS_JUMPS_HARNESS_MAIN = """
int main(void)
{
    if (nested_loops(5) != 42) {
        return 1;
    }
    if (goto_accumulate(4) != 14) {
        return 2;
    }
    return 255;
}
"""


POINTER_MEMORY_HARNESS_MAIN = """
int main(void)
{
    unsigned char bytes[8];
    unsigned short words[4];
    int a;
    int b;

    fill_bytes(bytes, 3, 8);
    words[0] = 10;
    words[1] = 20;
    words[2] = 30;
    words[3] = 40;
    a = 5;
    b = 9;
    swap_ptrs(&a, &b);
    if (bytes[2] != 3) {
        return 1;
    }
    if (sum_words(words, 4) != 100) {
        return 2;
    }
    if (a != 9 || b != 5) {
        return 3;
    }
    return 255;
}
"""


SCALAR_TYPES_HARNESS_MAIN: str = """
int main(void)
{
    char text1[4];
    char text2[4];
    char *picked;
    int total;

    text1[0] = 'A';
    text1[1] = 0;
    text2[0] = 'B';
    text2[1] = 0;
    picked = pick_ptr(text1, text2, 0);
    total = add_sc(1, 2);
    total += mix_uc(7, 3);
    total += sub_ss(9, 4);
    total += mul_us(3, 5);
    total += add_int(10, 20);
    total += rot_ui(9U);
    total += (int)add_long(1000L, 2000L);
    total += (int)sub_ulong(90UL, 30UL);
    if (add_sc(1, 2) != 3) {
        return 1;
    }
    if (mix_uc(64, 0) != (unsigned char)128) {
        return 2;
    }
    if (byteops_unsigned() != 0xC000U) {
        return 13;
    }
    if (sub_ss(9, 4) != 5) {
        return 3;
    }
    if (mul_us(3, 5) != 15) {
        return 4;
    }
    if (add_int(10, 20) != 30) {
        return 5;
    }
    if (rot_ui(9U) != 18U || rot_ui(0x8000U) != 1U ||
        rot_ui(0xffffU) != 0xffffU || rot_ui(0x0080U) != 0x0100U) {
        return 6;
    }
    if (add_long(1000L, 2000L) != 3000L) {
        return 7;
    }
    if (sub_ulong(90UL, 30UL) != 60UL) {
        return 8;
    }
    if (picked[0] != 'B') {
        return 9;
    }
    if (total == 0) {
        return 10;
    }
    return 255;
}
"""


EXAMPLES: dict[str, ExampleSpec] = {
    "simple_control": ExampleSpec(
        name="simple_control",
        exe=DEFAULT_BUILD_DIR / "SIMPLE.EXE",
        output_stem="SIMPLERT",
        functions=(
            FunctionSpec("classify", proc_kind="NEAR"),
            FunctionSpec("sum_to", proc_kind="NEAR"),
            FunctionSpec("switch_fold", proc_kind="NEAR"),
        ),
        harness_main=SIMPLE_CONTROL_HARNESS_MAIN,
    ),
    "cmp16": ExampleSpec(
        name="cmp16",
        exe=DEFAULT_BUILD_DIR / "CMP16.EXE",
        output_stem="CMP16RT",
        functions=(
            FunctionSpec("cmp_i16", proc_kind="NEAR"),
            FunctionSpec("rel_i16", proc_kind="NEAR"),
            FunctionSpec("rel_u16", proc_kind="NEAR"),
            FunctionSpec("clamp_u16", proc_kind="NEAR"),
            FunctionSpec("in_window_i16", proc_kind="NEAR"),
        ),
        harness_main=CMP16_HARNESS_MAIN,
    ),
    "cmp32": ExampleSpec(
        name="cmp32",
        exe=DEFAULT_BUILD_DIR / "COMP32.EXE",
        output_stem="CMP32RT",
        functions=(
            FunctionSpec("select_max", proc_kind="NEAR"),
            FunctionSpec("compare_signed", proc_kind="NEAR"),
            FunctionSpec("compare_unsigned", proc_kind="NEAR"),
            FunctionSpec("clamp_window", proc_kind="NEAR"),
            FunctionSpec("rel_signed32", proc_kind="NEAR"),
            FunctionSpec("rel_unsigned32", proc_kind="NEAR"),
        ),
        harness_main=CMP32_HARNESS_MAIN,
    ),
    "fptr": ExampleSpec(
        name="fptr",
        exe=DEFAULT_BUILD_DIR / "FPTR.EXE",
        output_stem="FPTRRT",
        functions=(
            FunctionSpec("inc_one", proc_kind="NEAR"),
            FunctionSpec("dec_one", proc_kind="NEAR"),
            FunctionSpec("apply_twice", proc_kind="NEAR"),
            FunctionSpec("select_and_apply", proc_kind="NEAR"),
        ),
        harness_main=FPTR_HARNESS_MAIN,
    ),
    "loops_jumps": ExampleSpec(
        name="loops_jumps",
        exe=DEFAULT_BUILD_DIR / "LOOPS.EXE",
        output_stem="LOOPSRT",
        functions=(
            FunctionSpec("nested_loops", proc_kind="NEAR"),
            FunctionSpec("goto_accumulate", proc_kind="NEAR"),
        ),
        harness_main=LOOPS_JUMPS_HARNESS_MAIN,
    ),
    "pointer_memory": ExampleSpec(
        name="pointer_memory",
        exe=DEFAULT_BUILD_DIR / "POINT.EXE",
        output_stem="POINTRT",
        functions=(
            FunctionSpec("fill_bytes", proc_kind="NEAR"),
            FunctionSpec("sum_words", proc_kind="NEAR"),
            FunctionSpec("swap_ptrs", proc_kind="NEAR"),
        ),
        harness_main=POINTER_MEMORY_HARNESS_MAIN,
    ),
    "scalar_types_io": ExampleSpec(
        name="scalar_types_io",
        exe=DEFAULT_BUILD_DIR / "TYPES.EXE",
        output_stem="TYPESRT",
        functions=(
            FunctionSpec("add_sc", proc_kind="NEAR"),
            FunctionSpec("mix_uc", proc_kind="NEAR"),
            FunctionSpec("byteops_unsigned", proc_kind="NEAR"),
            FunctionSpec("sub_ss", proc_kind="NEAR"),
            FunctionSpec("mul_us", proc_kind="NEAR"),
            FunctionSpec("add_int", proc_kind="NEAR"),
            FunctionSpec("rot_ui", proc_kind="NEAR"),
            FunctionSpec("add_long", proc_kind="NEAR"),
            FunctionSpec("sub_ulong", proc_kind="NEAR"),
            FunctionSpec("pick_ptr", proc_kind="NEAR"),
        ),
        harness_main=SCALAR_TYPES_HARNESS_MAIN,
    ),
}


class RuntimeGateError(RuntimeError):
    def __init__(self, stage: RuntimeGateStage, message: str) -> None:
        self.stage = stage
        super().__init__(f"{stage.name.lower()}: {message}")


def _run_decompile(
    spec: FunctionSpec,
    *,
    exe_path: Path,
    decompile_py: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run one isolated function decompilation with gate-only controls removed."""
    cmd = [
        sys.executable,
        str(decompile_py),
        "--alternate-source-c",
        "--timeout",
        str(timeout),
    ]
    if spec.addr is not None:
        cmd += ["--addr", spec.addr]
    else:
        cmd += ["--proc", spec.name, "--proc-kind", spec.proc_kind or "NEAR"]
    cmd.append(str(exe_path))

    env = dict(os.environ)
    env.pop("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", None)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout + 30,
        check=False,
    )


def _runtime_decompile_workers(function_count: int) -> int:
    """Return the bounded nested worker count for independent tiny functions."""
    requested_text = os.environ.get("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", "2")
    try:
        requested = int(requested_text)
    except ValueError as exc:
        raise RuntimeGateError(
            RuntimeGateStage.DECOMPILE,
            f"invalid INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS={requested_text!r}",
        ) from exc
    return min(2, function_count, max(1, requested))


def _assert_valid_decompile(spec: FunctionSpec, proc: subprocess.CompletedProcess[str]) -> str:
    combined = f"{proc.stderr}\n{proc.stdout}"
    if proc.returncode != 0:
        raise RuntimeGateError(
            RuntimeGateStage.DECOMPILE,
            f"{spec.name} decompile exited {proc.returncode}\n{combined[-4000:]}",
        )
    if "[tail-validation] whole-tail validation clean across 1 functions" not in combined:
        raise RuntimeGateError(
            RuntimeGateStage.DECOMPILE,
            f"{spec.name} did not report clean tail validation\n{combined[-4000:]}",
        )
    reject_markers = (
        "whole-tail validation failed",
        "tail validation not collected",
        "tail_validation_failed",
        "MS C 5.1 msc-dos syntax check failed",
        "MS C 6.0 msc-dos syntax check failed",
        "== asm fallback ==",
        "Decompilation timeout",
    )
    for marker in reject_markers:
        if marker in combined:
            raise RuntimeGateError(
                RuntimeGateStage.DECOMPILE,
                f"{spec.name} has rejected marker {marker!r}\n{combined[-4000:]}",
            )
    return proc.stdout


def _find_function_definition(c_text: str, function_name: str) -> str:
    emitted = c_text.split("/* == c == */", 1)[-1] if "/* == c == */" in c_text else c_text
    name_re = re.escape(function_name)
    signature_re = re.compile(
        rf"(?m)^(?P<signature>(?:(?:signed|unsigned)\s+)?(?:int|long|short|char|void)\s+\**\s*{name_re}\s*\([^;{{}}]*\))\s*\n+\s*\{{"
    )
    match = signature_re.search(emitted)
    if match is None:
        raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"missing generated definition for {function_name}")

    brace_start = emitted.find("{", match.end("signature"))
    if brace_start < 0:
        raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"missing opening brace for {function_name}")

    depth = 0
    for idx in range(brace_start, len(emitted)):
        ch = emitted[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return emitted[match.start("signature") : idx + 1].strip() + "\n"
    raise RuntimeGateError(RuntimeGateStage.EXTRACT, f"unterminated generated definition for {function_name}")


def _build_full_source(example: ExampleSpec, function_bodies: list[str]) -> str:
    """Assemble generated bodies with the ABI supplied by the linked runtime."""
    return "\n".join(
        [
            "#include <stdbool.h>",
            "#include <stdint.h>",
            msc6_runtime_state_declarations(),
            "",
            *function_bodies,
            "",
            textwrap.dedent(example.harness_main).strip(),
            "",
        ]
    )


def _verify_example(
    example: ExampleSpec,
    *,
    out_dir: Path,
    kvikdos: Path,
    msc6_root: Path,
    decompile_py: Path,
    expected_exit_code: int,
    timeout: int,
) -> Path:
    """Decompile, rebuild, and execute one evidence-backed runtime example."""
    if not example.exe.is_file():
        raise RuntimeGateError(RuntimeGateStage.DECOMPILE, f"missing example executable: {example.exe}")
    if not kvikdos.is_file():
        raise RuntimeGateError(RuntimeGateStage.RUN, f"missing kvikdos executable: {kvikdos}")
    if not msc6_root.is_dir():
        raise RuntimeGateError(RuntimeGateStage.COMPILE, f"missing MS C 6 root: {msc6_root}")

    out_dir.mkdir(parents=True, exist_ok=True)
    bodies: list[str] = []
    decompile_results: list[subprocess.CompletedProcess[str]] = []
    if example.functions:
        with ThreadPoolExecutor(max_workers=_runtime_decompile_workers(len(example.functions))) as executor:
            futures = tuple(
                executor.submit(
                    _run_decompile,
                    function,
                    exe_path=example.exe,
                    decompile_py=decompile_py,
                    timeout=timeout,
                )
                for function in example.functions
            )
            decompile_results = [future.result() for future in futures]
    for function, proc in zip(example.functions, decompile_results, strict=True):
        raw_path = out_dir / f"{example.output_stem}_{function.name}.dec.txt"
        err_path = out_dir / f"{example.output_stem}_{function.name}.dec.err.txt"
        raw_path.write_text(proc.stdout, encoding="utf-8")
        err_path.write_text(proc.stderr, encoding="utf-8")
        c_text = _assert_valid_decompile(function, proc)
        bodies.append(_find_function_definition(c_text, function.name))

    source_path = out_dir / f"{example.output_stem}.C"
    source_path.write_text(_build_full_source(example, bodies), encoding="utf-8")

    exe_name = f"{example.output_stem}.EXE"
    built_ok, compile_stdout, compile_stderr, link_stdout, link_stderr = _compile_and_link(
        source_path,
        out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        obj_name=f"{example.output_stem}.OBJ",
        exe_name=exe_name,
        map_name=f"{example.output_stem}.MAP",
        runtime_support=True,
    )
    (out_dir / f"{example.output_stem}.compile.out.txt").write_text(compile_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.compile.err.txt").write_text(compile_stderr, encoding="utf-8")
    (out_dir / f"{example.output_stem}.link.out.txt").write_text(link_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.link.err.txt").write_text(link_stderr, encoding="utf-8")
    if not built_ok:
        raise RuntimeGateError(
            RuntimeGateStage.COMPILE,
            f"MS C 6 rebuild failed\n{compile_stdout}{compile_stderr}{link_stdout}{link_stderr}",
        )

    rebuilt_exe = out_dir / exe_name
    _, run_exit, run_stdout, run_stderr = _run_example(
        rebuilt_exe,
        out_dir,
        kvikdos=kvikdos,
        timeout=timeout,
    )
    (out_dir / f"{example.output_stem}.run.out.txt").write_text(run_stdout, encoding="utf-8")
    (out_dir / f"{example.output_stem}.run.err.txt").write_text(run_stderr, encoding="utf-8")
    if run_exit != expected_exit_code:
        raise RuntimeGateError(
            RuntimeGateStage.RUN,
            f"rebuilt {example.name} exited {run_exit}, expected {expected_exit_code}\n{run_stdout}{run_stderr}",
        )
    return rebuilt_exe


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a decompiled MS C example by rebuilding and running it.")
    parser.add_argument("--example", choices=tuple(sorted(EXAMPLES)), default="cmp16")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    parser.add_argument("--decompile-py", type=Path, default=DEFAULT_DECOMPILE)
    parser.add_argument("--expected-exit-code", type=int, default=255)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--clean", action="store_true", help="Remove the output directory before running the gate.")
    args = parser.parse_args()

    if args.clean and args.out_dir.exists():
        shutil.rmtree(args.out_dir)

    example = EXAMPLES[args.example]
    try:
        rebuilt_exe = _verify_example(
            example,
            out_dir=args.out_dir,
            kvikdos=args.kvikdos,
            msc6_root=args.msc6_root,
            decompile_py=args.decompile_py,
            expected_exit_code=args.expected_exit_code,
            timeout=args.timeout,
        )
    except RuntimeGateError as exc:
        print(f"[runtime-gate] failed stage={exc.stage.name.lower()} error={exc}", file=sys.stderr)
        return 1

    print(
        f"[runtime-gate] example={example.name} rebuilt={rebuilt_exe} run_exit={args.expected_exit_code} status=passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
