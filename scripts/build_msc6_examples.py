#!/usr/bin/env python3
"""Build, decompile, rebuild, and run the MS C construct examples.

Layer: Tooling/gates.
Responsibility: owns MS C example build, decompile, rebuild, and run gates.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

from pycparser import c_ast, c_parser
from pycparser.c_parser import ParseError

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.lowering.gp_word_runtime import (  # noqa: E402
    DEFAULT_GP_RUNTIME_ABI_8616,
    GPRegisterRuntimeABI8616,
)

from inertia_decompiler.acceptance_scorecard import measure_x86_16_codegen_quality_8616  # noqa: E402
from inertia_decompiler.cli_terminal_status import CliTerminalStatus, read_terminal_status  # noqa: E402
from inertia_decompiler.flair_paths import default_flair_startup_root  # noqa: E402
from inertia_decompiler.project_loading import _build_project  # noqa: E402
from inertia_decompiler.sidecar_metadata import _load_lst_metadata  # noqa: E402
from scripts.decompile_process_budget import focused_decompile_process_timeout  # noqa: E402
from scripts.generated_c_return_contract import has_returned_call_8616  # noqa: E402
from scripts.msc6_function_targets import (  # noqa: E402
    BinaryFunctionTarget,
    TargetBindingStatus,
    bind_function_targets,
)
from scripts.msc6_memory_model import MSCMemoryModel  # noqa: E402
from scripts.msc6_original_evidence import record_original_execution  # noqa: E402
from scripts.msc6_pointer_memory_harness import POINTER_MEMORY_HARNESS_MAIN  # noqa: E402
from scripts.msc6_runtime_gate_artifacts import retain_focused_output  # noqa: E402
from scripts.msc6_runtime_support import (  # noqa: E402
    msc6_runtime_state_declarations,
    msc6_runtime_support_source,
)
from scripts.msc6_toolchain_lock import msc6_toolchain_lock  # noqa: E402
from signature_catalog import build_signature_catalog  # noqa: E402

DEFAULT_EXAMPLES_DIR: Path = REPO_ROOT / "examples" / "msc6_constructs"
DEFAULT_OUT_DIR: Path = REPO_ROOT / "examples" / "build_msc6"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_DECOMPILE: Path = REPO_ROOT / "decompile.py"
DEFAULT_BATCH_DECOMPILE_PROCS: Path = REPO_ROOT / "scripts" / "batch_decompile_procs.py"
DEFAULT_DECOMPILE_SKIP: tuple[str, ...] = ()
HARNESS_SUCCESS_EXIT_CODE = 255
DECOMPILE_MAX_FUNCTIONS_DEFAULT = 0
DEFAULT_SIGNATURE_CATALOG_NAME = "runtime_signature_catalog.pat"
DECOMPILE_MAIN_NAMES = ("main", "MAIN", "_main", "_MAIN", "start", "_start")
DECOMPILE_MAIN_TIMEOUT_SECONDS_DEFAULT = 60
DECOMPILE_MAIN_RUN_TIMEOUT_SECONDS_DEFAULT = 60
DECOMPILE_SLOW_FUNCTION_SECONDS = 1.0
DECOMPILE_SLOW_PASS_SECONDS = 1.0


class HarnessAcceptanceReason(StrEnum):
    """Reason a harness decompilation result was accepted or stopped."""

    ACCEPTANCE_GATE_FAILED = "acceptance_gate_failed"
    ASM_FALLBACK = "asm_fallback"
    SOURCE_EVIDENCE_FAILED = "source_evidence_failed"
    TAIL_VALIDATION_CHANGED = "tail_validation_changed"
    TAIL_VALIDATION_FAILED = "tail_validation_failed"
    TAIL_VALIDATION_UNCOLLECTED = "tail_validation_uncollected"
    TIMEOUT = "timeout"
    VALIDATION_CHANGED = "validation_changed"
    VALIDATION_FAILED = "validation_failed"
    VALIDATION_UNCOLLECTED = "validation_uncollected"


class HarnessValidationState(StrEnum):
    """Typed function-level validation state parsed from decompiler output."""

    CHANGED = "changed"
    FAILED = "failed"
    PASSED = "passed"
    UNCOLLECTED = "uncollected"


class HarnessTailValidationState(StrEnum):
    """Typed final whole-tail state parsed from decompiler output."""

    CLEAN = "clean"
    FAILED = "failed"
    PASSED = "passed"
    UNCOLLECTED = "uncollected"


class FocusedDecompileRetryReason(StrEnum):
    """Reason to retry focused decompilation with a different fallback mode."""

    ASM_FALLBACK = "asm_fallback"
    MISSING_GENERATED_DEFINITION = "missing_generated_definition"
    NONZERO_EXIT = "nonzero_exit"
    TAIL_VALIDATION_FAILED = "tail_validation_failed"
    TIMEOUT = "timeout"


class GeneratedFunctionSourceContractStatus(StrEnum):
    """Typed result of checking one generated function definition."""

    PASSED = "passed"
    FUNCTION_MISSING = "function_missing"
    FUNCTION_PARSE_FAILED = "function_parse_failed"
    GLOBAL_SHADOWED_BY_LOCAL = "global_shadowed_by_local"
    GLOBAL_WRITE_MISSING = "global_write_missing"
    VALUE_RETURN_REQUIRED = "value_return_required"
    VOID_RETURN_REQUIRED = "void_return_required"
    RETURNED_CALL_MISSING = "returned_call_missing"


class GeneratedFunctionReturnClass(StrEnum):
    """Required return class for one generated-function gate contract."""

    ANY = "any"
    VALUE = "value"
    VOID = "void"


@dataclass(frozen=True, slots=True)
class GeneratedFunctionSourceContract:
    """Required source shape for a generated function in an MS C gate.

    This is a test-pipeline assertion, not decompiler recovery. It consumes the
    final generated C and refuses a known false-green shape before compilation.
    """

    function_name: str
    required_return_class: GeneratedFunctionReturnClass = (
        GeneratedFunctionReturnClass.ANY
    )
    required_returned_call: str | None = None
    required_global_writes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GeneratedFunctionSourceContractResult:
    """Evidence and verdict for one generated-function source contract."""

    function_name: str
    status: GeneratedFunctionSourceContractStatus
    required_return_class: GeneratedFunctionReturnClass
    required_returned_call: str | None
    materialized_return_class: GeneratedFunctionReturnClass | None
    returned_call_present: bool
    required_global_writes: tuple[str, ...]
    materialized_global_writes: tuple[str, ...]
    shadowed_global_writes: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether all configured source requirements were proven."""
        return self.status is GeneratedFunctionSourceContractStatus.PASSED

    def to_dict(self) -> dict[str, object]:
        """Return JSON-safe evidence for the fallback rebuild report."""
        return {
            "function_name": self.function_name,
            "status": self.status.value,
            "required_return_class": self.required_return_class.value,
            "required_returned_call": self.required_returned_call,
            "materialized_return_class": (
                self.materialized_return_class.value
                if self.materialized_return_class is not None
                else None
            ),
            "returned_call_present": self.returned_call_present,
            "required_global_writes": list(self.required_global_writes),
            "materialized_global_writes": list(self.materialized_global_writes),
            "shadowed_global_writes": list(self.shadowed_global_writes),
        }


def _decompile_python_executable() -> str:
    return sys.executable or str(shutil.which("python3") or "python3")


def _focused_decompile_process_timeout(decompile_timeout: int) -> int:
    """Return subprocess budget separate from the inner decompiler analysis timeout."""

    return int(focused_decompile_process_timeout(decompile_timeout))


def _focused_decompile_retry_reason(profile: dict[str, object]) -> FocusedDecompileRetryReason | None:
    reason = profile.get("acceptance_reason")
    for retry_reason in FocusedDecompileRetryReason:
        if reason == retry_reason.value:
            return retry_reason
    return None


def _attach_decompile_quality_profile(
    profile: dict[str, object],
    c_text: str,
    *,
    function_name: str = "unknown",
) -> None:
    metrics = measure_x86_16_codegen_quality_8616(
        c_text,
        function_name=function_name,
        asm_fallback=bool(profile.get("asm_fallback")),
        validation_uncollected=bool(profile.get("tail_validation_uncollected")),
    )
    profile["quality"] = metrics.to_dict()


COMPARE16_HARNESS_MAIN = """
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
    if (rel_i16(-32767 - 1, 32767) != 35 || rel_i16(32767, -32767 - 1) != 44) {
        return 14;
    }
    if (rel_u16(65535U, 0U) != 44 || rel_u16(32768U, 32767U) != 44) {
        return 15;
    }
    if (add_wrap_u16(65535U, 1U) != 0U || add_wrap_u16(32767U, 1U) != 32768U ||
        add_wrap_u16(32768U, 32768U) != 0U) {
        return 16;
    }
    return 255;
}
"""

COMPARE32_HARNESS_MAIN = """
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

FNPTR_HARNESS_MAIN = """
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
    if (nested_arguments(2) != 50 || nested_arguments(-3) != -5 ||
        nested_arguments(0) != 28) {
        return 5;
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

MEDIUM_STRUCTS_PREFIX = """
struct Pair {
    int left;
    int right;
};
"""

MEDIUM_STRUCTS_HARNESS_MAIN = """
int main(void)
{
    struct Pair pairs[3];
    int values[4];
    int total;
    int pos;

    pairs[0].left = 1;
    pairs[0].right = 3;
    pairs[1].left = 2;
    pairs[1].right = 5;
    pairs[2].left = 4;
    pairs[2].right = 7;

    values[0] = 4;
    values[1] = 8;
    values[2] = 15;
    values[3] = 16;

    rotate_triplet(values);
    total = accumulate_pairs(pairs, 3);
    pos = find_first_gt(values, 4, 10);
    if (values[0] != 8 || values[1] != 15 || values[2] != 4) {
        return 1;
    }
    if (total != 29) {
        return 2;
    }
    if (pos != 1) {
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
    total += 7;
    total += 8;
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
    if (7 != 7) {
        return 9;
    }
    if (8 != 8) {
        return 10;
    }
    if (picked[0] != 'B') {
        return 11;
    }
    if (total == 0) {
        return 12;
    }
    return 255;
}
"""

STORAGE_CLASSES_PREFIX = """
unsigned short g_counter = 3;
unsigned char g_table[4] = { 1, 2, 3, 4 };
unsigned short seen = 10;
"""

STORAGE_CLASSES_HARNESS_MAIN: str = """
int main(void)
{
    int total;

    total = _sum_globals();
    if (total != 13) {
        return 1;
    }
    if (bump_static() != 12) {
        return 2;
    }
    if (bump_static() != 14) {
        return 3;
    }
    /* Exercise pre-store values on both sides of a byte carry. */
    g_counter = 242;
    if (_sum_globals() != 252) {
        return 4;
    }
    g_counter = 246;
    if (_sum_globals() != 256) {
        return 5;
    }
    return 255;
}
"""

SORTDEMO_PATTERNS_HARNESS_MAIN = """
int main(void)
{
    if (sortdemo_loop_bound() != 15) {
        return 1;
    }
    if (sortdemo_descend_count(4) != 10) {
        return 2;
    }
    if (sortdemo_global_pair_sum() != 12) {
        return 3;
    }
    if (sortdemo_adjacent_gt(1) != 1) {
        return 4;
    }
    if (sortdemo_adjacent_gt(2) != 0) {
        return 5;
    }
    sortdemo_reset_work();
    if (sortdemo_adjacent_swap_once(1) != 1) {
        return 6;
    }
    if (g_work[0] != 1 || g_work[1] != 9) {
        return 7;
    }
    if (sortdemo_adjacent_swap_once(2) != 1) {
        return 8;
    }
    if (g_work[1] != 5 || g_work[2] != 9) {
        return 9;
    }
    sortdemo_reset_work();
    if (sortdemo_single_pass_swap() != 11) {
        return 10;
    }
    if (g_work[0] != 1 || g_work[5] != 9) {
        return 11;
    }
    sortdemo_reset_work();
    if (sortdemo_switch_loop() != 10) {
        return 12;
    }
    if (g_work[0] != 1 || g_work[5] != 9) {
        return 13;
    }
    sortdemo_reset_work();
    if (sortdemo_pivot_scan(0, 5) != 4) {
        return 14;
    }
    if (g_work[0] != 2 || g_work[3] != 9) {
        return 15;
    }
    sortdemo_exchangedata_init();
    sortdemo_heap_percolate_up(4);
    if (g_demo_len[1] != 8 || g_demo_len[2] != 1 || g_demo_len[4] != 5) {
        return 16;
    }
    if (g_demo_bar[1] != 4 || g_demo_bar[2] != 1 || g_demo_bar[4] != 2) {
        return 17;
    }
    return 255;
}
"""

ENUM_UNION_PREFIX = """
enum TokenKind {
    TOK_ZERO,
    TOK_ONE,
    TOK_TWO,
    TOK_MANY
};
"""

ENUM_UNION_HARNESS_MAIN = """
int main(void)
{
    unsigned short combined;

    combined = combine_bytes(0x34, 0x12);
    if (token_cost(TOK_TWO) != 2) {
        return 1;
    }
    if (token_cost(TOK_MANY) != 9) {
        return 2;
    }
    if (combined != 0x1234) {
        return 3;
    }
    return 255;
}
"""

FALLBACK_EXAMPLE_REBUILD: dict[str, dict[str, object]] = {
    "simple_control": {
        "functions": ("classify", "sum_to", "switch_fold"),
        "harness": SIMPLE_CONTROL_HARNESS_MAIN,
    },
    "compare16": {
        "functions": ("cmp_i16", "rel_i16", "rel_u16", "clamp_u16", "in_window_i16", "add_wrap_u16"),
        "harness": COMPARE16_HARNESS_MAIN,
    },
    "compare32": {
        "functions": (
            "select_max",
            "compare_signed",
            "compare_unsigned",
            "clamp_window",
            "rel_signed32",
            "rel_unsigned32",
        ),
        "harness": COMPARE32_HARNESS_MAIN,
    },
    "function_pointers": {
        "functions": ("inc_one", "dec_one", "apply_twice", "select_and_apply", "combine_args", "nested_arguments"),
        "harness": FNPTR_HARNESS_MAIN,
        "source_contracts": (
            GeneratedFunctionSourceContract(
                function_name="select_and_apply",
                required_return_class=GeneratedFunctionReturnClass.VALUE,
                required_returned_call="apply_twice",
            ),
        ),
    },
    "loops_jumps": {
        "functions": ("nested_loops", "goto_accumulate"),
        "harness": LOOPS_JUMPS_HARNESS_MAIN,
    },
    "pointer_memory": {
        "functions": ("fill_bytes", "sum_words", "swap_ptrs", "offset_copy", "select_word"),
        "harness": POINTER_MEMORY_HARNESS_MAIN,
        "source_contracts": (
            GeneratedFunctionSourceContract(
                function_name="fill_bytes",
                required_return_class=GeneratedFunctionReturnClass.ANY,
            ),
            GeneratedFunctionSourceContract(
                function_name="sum_words",
                required_return_class=GeneratedFunctionReturnClass.VALUE,
            ),
            GeneratedFunctionSourceContract(
                function_name="swap_ptrs",
                required_return_class=GeneratedFunctionReturnClass.ANY,
            ),
            GeneratedFunctionSourceContract(
                function_name="select_word",
                required_return_class=GeneratedFunctionReturnClass.VALUE,
            ),
        ),
    },
    "medium_structs": {
        "functions": ("accumulate_pairs", "rotate_triplet", "find_first_gt"),
        "prefix": MEDIUM_STRUCTS_PREFIX,
        "harness": MEDIUM_STRUCTS_HARNESS_MAIN,
    },
    "scalar_types_io": {
        "functions": (
            "add_sc",
            "mix_uc",
            "byteops_unsigned",
            "sub_ss",
            "mul_us",
            "add_int",
            "rot_ui",
            "add_long",
            "sub_ulong",
            "pick_ptr",
        ),
        "harness": SCALAR_TYPES_HARNESS_MAIN,
    },
    "storage_classes": {
        "functions": ("_sum_globals", "bump_static"),
        "prefix": STORAGE_CLASSES_PREFIX,
        "harness": STORAGE_CLASSES_HARNESS_MAIN,
        "source_contracts": (
            GeneratedFunctionSourceContract(
                function_name="bump_static",
                required_global_writes=("seen",),
            ),
        ),
    },
    "sortdemo_patterns": {
        "functions": (
            "sortdemo_reset_work",
            "sortdemo_loop_bound",
            "sortdemo_descend_count",
            "sortdemo_global_pair_sum",
            "sortdemo_adjacent_gt",
            "sortdemo_adjacent_swap_once",
            "sortdemo_single_pass_swap",
            "sortdemo_switch_loop",
            "sortdemo_pivot_scan",
            "DrawTime",
            "Swaps",
            "SwapBars",
            "sortdemo_exchangedata_init",
            "sortdemo_exchange_sort",
            "sortdemo_heap_percolate_up",
        ),
        "prefix": (
            "unsigned short g_rows = 6;\n"
            "unsigned short g_work[8] = { 9, 1, 5, 2, 8, 3, 7, 4 };\n"
            "unsigned short g_demo_rows = 6;\n"
            "unsigned short g_demo_len[6] = { 9, 1, 5, 2, 8, 3 };\n"
            "unsigned short g_demo_bar[6] = { 0, 1, 2, 3, 4, 5 };\n"
            "unsigned short g_demo_draw_calls = 0;\n"
            "unsigned short g_demo_draw_last = 0;\n"
        ),
        "harness": SORTDEMO_PATTERNS_HARNESS_MAIN,
    },
    "enum_union": {
        "functions": ("token_cost", "combine_bytes"),
        "prefix": ENUM_UNION_PREFIX,
        "harness": ENUM_UNION_HARNESS_MAIN,
    },
}


def _extract_decompiled_function_definition(c_text: str, function_name: str) -> str:
    """Select a generated definition without repairing its signature or body."""
    emitted = c_text.split("/* == c == */", 1)[-1] if "/* == c == */" in c_text else c_text
    candidate_names = tuple(dict.fromkeys((function_name, function_name.lstrip("_"), f"_{function_name.lstrip('_')}")))
    match, matched_name = _locate_generated_signature(emitted, candidate_names, function_name)
    if match is None:
        raise RuntimeError(f"missing generated definition for {function_name}")

    brace_start = emitted.find("{", match.end("signature"))
    if brace_start < 0:
        raise RuntimeError(f"missing opening brace for {matched_name}")

    end = _balanced_brace_end(emitted, brace_start)
    if end is None:
        raise RuntimeError(f"unterminated generated definition for {matched_name}")
    return emitted[match.start("signature") : end].strip() + "\n"


def _locate_generated_signature(
    emitted: str,
    candidate_names: tuple[str, ...],
    function_name: str,
) -> tuple[re.Match[str] | None, str]:
    """Locate the generated definition signature, falling back per candidate."""
    for candidate_name in candidate_names:
        signature_re = re.compile(
            rf"(?m)^[ \t]*(?!/)(?P<signature>[A-Za-z_*][^\n]*\b{re.escape(candidate_name)}\s*\([^\n)]*\))\s*(\n|\r\n|\r)\s*\{{"
        )
        match = signature_re.search(emitted)
        if match is not None:
            return match, candidate_name
        fallback_line_re = re.compile(
            rf"(?mi)^[ \t]*(?!/)(?P<signature>[A-Za-z_*][^\n]*\b{re.escape(candidate_name)}\s*\([^\n)]*\))"
        )
        for fallback_match in fallback_line_re.finditer(emitted):
            fallback_span_end = fallback_match.end("signature")
            fallback_brace_start = emitted.find("{", fallback_span_end)
            if fallback_brace_start >= 0:
                return fallback_match, candidate_name
    return None, function_name


def _balanced_brace_end(emitted: str, brace_start: int) -> int | None:
    """Return the offset just past the matching close brace."""
    depth = 0
    for idx in range(brace_start, len(emitted)):
        ch = emitted[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return None


def _missing_function_contract_result(
    contract: GeneratedFunctionSourceContract,
) -> GeneratedFunctionSourceContractResult:
    """Return the FUNCTION_MISSING verdict for an unextractable definition."""
    return GeneratedFunctionSourceContractResult(
        function_name=contract.function_name,
        status=GeneratedFunctionSourceContractStatus.FUNCTION_MISSING,
        required_return_class=contract.required_return_class,
        required_returned_call=contract.required_returned_call,
        materialized_return_class=None,
        returned_call_present=False,
        required_global_writes=contract.required_global_writes,
        materialized_global_writes=(),
        shadowed_global_writes=(),
    )


def _contract_status(
    contract: GeneratedFunctionSourceContract,
    *,
    parse_failed: bool,
    materialized_return_class: GeneratedFunctionReturnClass | None,
    returned_call_present: bool,
    materialized_global_writes: tuple[str, ...],
    shadowed_global_writes: tuple[str, ...],
) -> GeneratedFunctionSourceContractStatus:
    """Select the contract verdict from measured facts."""
    if parse_failed:
        return GeneratedFunctionSourceContractStatus.FUNCTION_PARSE_FAILED
    if (
        contract.required_return_class is GeneratedFunctionReturnClass.VALUE
        and materialized_return_class is not GeneratedFunctionReturnClass.VALUE
    ):
        return GeneratedFunctionSourceContractStatus.VALUE_RETURN_REQUIRED
    if (
        contract.required_return_class is GeneratedFunctionReturnClass.VOID
        and materialized_return_class is not GeneratedFunctionReturnClass.VOID
    ):
        return GeneratedFunctionSourceContractStatus.VOID_RETURN_REQUIRED
    if not returned_call_present:
        return GeneratedFunctionSourceContractStatus.RETURNED_CALL_MISSING
    if shadowed_global_writes:
        return GeneratedFunctionSourceContractStatus.GLOBAL_SHADOWED_BY_LOCAL
    if materialized_global_writes != contract.required_global_writes:
        return GeneratedFunctionSourceContractStatus.GLOBAL_WRITE_MISSING
    return GeneratedFunctionSourceContractStatus.PASSED


def _written_storage_name_8616(node: c_ast.Node) -> str | None:
    """Return the root identifier written by one parsed C lvalue."""
    if isinstance(node, c_ast.ID):
        return cast(str, node.name)
    if isinstance(node, c_ast.ArrayRef):
        return _written_storage_name_8616(node.name)
    if isinstance(node, c_ast.StructRef):
        return _written_storage_name_8616(node.name)
    return None


class _GeneratedFunctionStorageCollector8616(c_ast.NodeVisitor):  # type: ignore[misc]
    """Collect local declarations and direct storage writes from parsed C."""

    def __init__(self) -> None:
        """Initialize deterministic local-name and write-name sets."""
        self.local_names: set[str] = set()
        self.written_names: set[str] = set()

    def visit_Decl(self, node: c_ast.Decl) -> None:
        """Record one function-body declaration and visit its initializer."""
        if isinstance(node.name, str):
            self.local_names.add(node.name)
        self.generic_visit(node)

    def visit_Assignment(self, node: c_ast.Assignment) -> None:
        """Record the root storage identifier written by an assignment."""
        name = _written_storage_name_8616(node.lvalue)
        if name is not None:
            self.written_names.add(name)
        self.generic_visit(node)

    def visit_UnaryOp(self, node: c_ast.UnaryOp) -> None:
        """Record increment/decrement writes while preserving nested traversal."""
        if node.op in {"p++", "p--", "++", "--"}:
            name = _written_storage_name_8616(node.expr)
            if name is not None:
                self.written_names.add(name)
        self.generic_visit(node)


def _parse_generated_function_definition_8616(
    definition: str,
) -> c_ast.FuncDef:
    """Parse one extracted generated function for test-contract validation."""
    without_block_comments = re.sub(r"/\*.*?\*/", "", definition, flags=re.DOTALL)
    parse_text = "\n".join(
        re.sub(r"//.*$", "", line)
        for line in without_block_comments.splitlines()
    )
    translation_unit = c_parser.CParser().parse(parse_text)
    function = next(
        (
            item
            for item in translation_unit.ext
            if isinstance(item, c_ast.FuncDef)
        ),
        None,
    )
    if function is None:
        raise ParseError("generated definition did not parse as a function")
    return function


def _generated_function_return_class_8616(
    function: c_ast.FuncDef,
) -> GeneratedFunctionReturnClass:
    """Classify the parsed function's top-level return type as void or value."""
    function_type = function.decl.type
    if not isinstance(function_type, c_ast.FuncDecl):
        raise ParseError("generated definition has no function declaration")
    return_type = function_type.type
    if (
        isinstance(return_type, c_ast.TypeDecl)
        and isinstance(return_type.type, c_ast.IdentifierType)
        and tuple(return_type.type.names) == ("void",)
    ):
        return GeneratedFunctionReturnClass.VOID
    return GeneratedFunctionReturnClass.VALUE


def _evaluate_generated_function_source_contract(
    c_text: str,
    contract: GeneratedFunctionSourceContract,
) -> GeneratedFunctionSourceContractResult:
    """Evaluate one contract against an extracted final C definition."""
    try:
        definition = _extract_decompiled_function_definition(c_text, contract.function_name)
    except RuntimeError:
        return _missing_function_contract_result(contract)

    returned_call_present = contract.required_returned_call is None

    materialized_global_writes: tuple[str, ...] = ()
    shadowed_global_writes: tuple[str, ...] = ()
    materialized_return_class: GeneratedFunctionReturnClass | None = None
    parse_failed = False
    try:
        function = _parse_generated_function_definition_8616(definition)
        materialized_return_class = _generated_function_return_class_8616(function)
    except ParseError:
        parse_failed = True
    else:
        if contract.required_returned_call is not None:
            returned_call_present = has_returned_call_8616(function, contract.required_returned_call)
        if contract.required_global_writes:
            storage = _GeneratedFunctionStorageCollector8616()
            storage.visit(function.body)
            materialized_global_writes = tuple(
                name
                for name in contract.required_global_writes
                if name in storage.written_names
            )
            shadowed_global_writes = tuple(
                name
                for name in contract.required_global_writes
                if name in storage.local_names
            )

    status = _contract_status(
        contract,
        parse_failed=parse_failed,
        materialized_return_class=materialized_return_class,
        returned_call_present=returned_call_present,
        materialized_global_writes=materialized_global_writes,
        shadowed_global_writes=shadowed_global_writes,
    )
    return GeneratedFunctionSourceContractResult(
        function_name=contract.function_name,
        status=status,
        required_return_class=contract.required_return_class,
        required_returned_call=contract.required_returned_call,
        materialized_return_class=materialized_return_class,
        returned_call_present=returned_call_present,
        required_global_writes=contract.required_global_writes,
        materialized_global_writes=materialized_global_writes,
        shadowed_global_writes=shadowed_global_writes,
    )


def _evaluate_generated_function_source_contracts(
    c_text: str,
    contracts: tuple[GeneratedFunctionSourceContract, ...],
) -> tuple[GeneratedFunctionSourceContractResult, ...]:
    """Evaluate all configured generated-C contracts deterministically."""
    return tuple(_evaluate_generated_function_source_contract(c_text, contract) for contract in contracts)


def _build_fallback_source(
    function_bodies: list[str], harness_main: str, *, prefix: str = "", harness_bindings: str = "",
) -> str:
    """Combine extracted bodies with their target runtime ABI and behavior harness."""
    from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

    prefix_text = textwrap.dedent(prefix).strip()
    prefix_lines = [prefix_text, ""] if prefix_text else []
    return "\n".join(
        [
            "#include <stdbool.h>",
            render_c_runtime_header_8616("msc-dos"),
            "void inertia_init_segments(void);",
            "",
            *prefix_lines,
            *function_bodies,
            "",
            harness_bindings,
            "#define main inertia_case_main",
            textwrap.dedent(harness_main).strip(),
            "#undef main",
            "int main(void) { inertia_init_segments(); return inertia_case_main(); }",
            "",
        ]
    )


def _safe_trace_label(text: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", text.strip())
    return label.strip("._-") or "child"


def _child_trace_path(base_path: str, label: str) -> str:
    path = Path(base_path)
    safe_label = _safe_trace_label(label)
    if path.suffix:
        return str(path.with_name(f"{path.stem}.{safe_label}{path.suffix}"))
    return str(path.with_name(f"{path.name}.{safe_label}"))


def _make_decompile_env(force_rizin_8616: bool, *, trace_label: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    if force_rizin_8616:
        env["INERTIA_AUTO_RIZIN_8616"] = "1"
    parent_trace_file = os.environ.get("INERTIA_OTEL_SPAN_FILE")
    if parent_trace_file and trace_label:
        env["INERTIA_OTEL_SPAN_FILE"] = _child_trace_path(parent_trace_file, trace_label)
    return env


@dataclass(frozen=True)
class ExampleResult:
    """Build, decompile, rebuild, and runtime result for one construct example."""

    name: str
    source: str
    exe: str
    obj: str
    map: str
    cod: str
    build_ok: bool
    run_ok: bool
    run_exit_code: int | None
    run_stdout: str
    run_stderr: str
    decompile_skipped: bool
    decompile_ok: bool
    decompile_recompiled: bool
    decompile_recompile_ok: bool
    decompile_run_ok: bool
    decompile_run_exit_code: int | None
    decompile_recompiled_exe: str
    decompile_recompiled_obj: str
    decompile_recompiled_map: str
    decompile_compile_stdout: str
    decompile_compile_stderr: str
    decompile_link_stdout: str
    decompile_link_stderr: str
    decompile_run_stdout: str
    decompile_run_stderr: str
    compile_stdout: str
    compile_stderr: str
    link_stdout: str
    link_stderr: str
    decompile_stdout_path: str | None
    decompile_stderr_path: str | None
    decompile_wall_seconds: float
    decompile_selected_functions: int
    decompile_profile: str


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command with captured output and explicit environment overrides."""

    runtime_env = os.environ.copy()
    if env is not None:
        runtime_env.update(env)
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=runtime_env,
    )


def _prepare_signature_catalog(
    *,
    signature_inputs: list[Path],
    signature_catalog_output: Path | None,
    signature_cache_dir: Path | None,
    build_root: Path,
    default_catalog_name: str,
) -> Path | None:
    if not signature_inputs:
        return None

    output_path = signature_catalog_output
    if output_path is None:
        output_path = build_root / "signature_catalogs" / default_catalog_name

    prepared_output = output_path if output_path.is_absolute() else (build_root / output_path).resolve()

    cache_dir = signature_cache_dir
    if cache_dir is None:
        cache_dir = prepared_output.parent / ".signature_catalog_cache"
    elif not cache_dir.is_absolute():
        cache_dir = build_root / cache_dir

    result = build_signature_catalog(
        tuple(path.resolve() for path in signature_inputs),
        prepared_output,
        recursive=True,
        cache_dir=cache_dir,
        flair_root=default_flair_startup_root(),
    )
    print(
        f"prepared signature catalog: {result.output_path} "
        f"inputs={result.input_count} "
        f"unique_modules={result.unique_module_count} "
        f"duplicates={result.duplicate_module_count}"
    )
    catalog_path: Path = result.output_path
    return catalog_path


def _dos_safe_names(stem: str, counter: int | None = None) -> tuple[str, str, str, str]:
    """Return distinct DOS-friendly names for rebuilt decompiler artifacts."""
    normalized = "".join(ch for ch in stem.upper() if ch.isalnum())
    if not normalized:
        normalized = "DECOMPILE"

    source_core = normalized[:8]
    sequence = max(counter or 0, 0) % 100
    short_core = next(
        candidate
        for marker in ("D", "R")
        if (candidate := f"{marker}{normalized[:4]}{sequence:02d}") != source_core
    )

    return (
        f"{short_core}.C",
        f"{short_core}.OBJ",
        f"{short_core}.EXE",
        f"{short_core}.MAP",
    )


def _ensure_msvc6_compat_headers(out_dir: Path) -> None:
    """Emit minimal stdbool/stdint shims when the MS C test root misses them."""
    from scripts.msc6_compat_headers import write_msc6_compat_headers

    write_msc6_compat_headers(out_dir)


def _sanitize_decompiled_source(raw_c_text: str) -> str:
    keep_lines: list[str] = []
    slash_comment_prefix = "///"
    for line in raw_c_text.splitlines():
        stripped = line.lstrip()
        if (
            stripped.startswith(("[dbg]", "[metric]", "[warn]", "[err]"))
        ):
            continue
        if stripped.startswith(slash_comment_prefix):
            # MS C 5.x/6.x toolchains are not guaranteed to support C++-style
            # line comments; drop these debug annotation lines before rebuild.
            continue
        keep_lines.append(line)
    return "\n".join(keep_lines) + ("\n" if raw_c_text.endswith("\n") else "")


def _prepare_decompiled_source_for_c89(raw_c_text: str) -> str:
    """Prepare decompiler output for legacy MS C 5.x/6.x compilers.

    Preserve emitted semantics; add only target runtime declarations and
    forward declarations copied from emitted signatures. Missing storage,
    unresolved stack carriers and signature collisions must fail compilation,
    not be recovered using harness/source knowledge.

    * strip unsupported debug marker lines,
    * inject forward declarations for emitted function definitions so call sites that
      appear before function bodies are compiled with correct signatures.
    """
    sanitized = _sanitize_decompiled_source(raw_c_text)
    sanitized = msc6_runtime_state_declarations() + sanitized
    return _inject_ms_c89_forward_decls(sanitized)


def _inject_ms_c89_forward_decls(raw_c_text: str) -> str:
    """MS C 5.x/6.x compilers predate mandatory modern prototypes.

    If a function is used before its definition, implicit declarations can
    generate stale return-type assumptions and spuriously fail with
    redefinition diagnostics. Inject forward declarations from emitted function
    signatures so decompiled output links on legacy compilers.
    """
    signature_re = re.compile(r"(?m)^([A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\r?\n\s*\{")
    declarations: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for match in signature_re.finditer(raw_c_text):
        function_name = match.group(2)
        if function_name in {"", "main", "main_"}:
            continue

        return_type = match.group(1).strip()
        args = match.group(3).strip()
        if not return_type:
            continue

        signature = (return_type, function_name, args)
        if signature in seen:
            continue
        seen.add(signature)
        declarations.append(f"{return_type} {function_name}({args});")

    if not declarations:
        return raw_c_text

    lines = raw_c_text.splitlines()
    first_match = signature_re.search(raw_c_text)
    if first_match is None:
        return raw_c_text

    insert_idx = len(raw_c_text[: first_match.start(0)].splitlines())

    if insert_idx <= 0:
        return raw_c_text

    decl_block = "\n".join(["", *declarations, ""])
    return "\n".join(lines[:insert_idx]) + "\n" + decl_block + "\n".join(lines[insert_idx:])


def _lookup_sidecar_code_labels(binary_path: Path) -> dict[str, int]:
    """Read labels belonging to the fixture's linked binary and build sidecars."""
    project = _build_project(
        binary_path,
        force_blob=False,
        base_addr=0x10000,
        entry_point=0,
    )
    metadata = _load_lst_metadata(binary_path, project, pat_backend=None, signature_catalog=None)
    labels: dict[str, int] = {}
    if metadata is None:
        return labels
    for addr, name in metadata.code_labels.items():
        if not isinstance(name, str):
            continue
        normalized = name.lower()
        labels[normalized] = int(addr)
        labels[normalized.lstrip("_")] = int(addr)
    return labels


def _compile_and_link_unlocked(
    source_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc6_root: Path,
    obj_name: str,
    exe_name: str,
    map_name: str,
    cod_name: str | None = None,
    runtime_support: bool = False,
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
    gp_runtime_abi: GPRegisterRuntimeABI8616 = DEFAULT_GP_RUNTIME_ABI_8616,
) -> tuple[bool, str, str, str, str]:
    """Compile and link while the caller owns the shared toolchain lock."""
    _ensure_msvc6_compat_headers(out_dir)
    artifact_names = [obj_name, exe_name, map_name]
    if cod_name is not None:
        artifact_names.append(cod_name)
    for artifact_name in artifact_names:
        with contextlib.suppress(OSError):
            (out_dir / artifact_name).unlink()
    compile_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--path-dos=e:\\BIN",
        "--env=INCLUDE=E:\\INCLUDE",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\CL.EXE",
        "e:\\BIN\\CL.EXE",
        "/Ic:\\",
        "/nologo",
        "/Od",
        memory_model.compiler_flag,
        "/c",
        f"/Foc:\\{obj_name}",
    ]
    if cod_name is not None:
        compile_cmd += [f"/Fcc:\\{cod_name}"]

    compile_cmd.append(f"c:\\{source_path.name}")
    compile_proc = _run(compile_cmd, timeout=120)

    runtime_obj_name = "INERTIA.OBJ"
    runtime_compile_stdout = ""
    runtime_compile_stderr = ""
    runtime_link_obj = ""
    if runtime_support:
        runtime_src = out_dir / "INERTIA.C"
        runtime_src.write_text(
            msc6_runtime_support_source(gp_runtime_abi, dos_segment_state=True),
            encoding="utf-8",
        )
        runtime_compile_cmd = [
            str(kvikdos),
            f"--mount=c:{out_dir}/",
            f"--mount=e:{msc6_root}/",
            "--drive=c",
            "--cwd-dos=c:\\",
            "--path-dos=e:\\BIN",
            "--env=INCLUDE=E:\\INCLUDE",
            "--env=LIB=E:\\LIB",
            "--prog=e:\\BIN\\CL.EXE",
            "e:\\BIN\\CL.EXE",
            "/Ic:\\",
            "/nologo",
            "/Od",
            memory_model.compiler_flag,
            "/c",
            f"/Foc:\\{runtime_obj_name}",
            "c:\\INERTIA.C",
        ]
        runtime_compile_proc = _run(runtime_compile_cmd, timeout=120)
        runtime_compile_stdout = runtime_compile_proc.stdout
        runtime_compile_stderr = runtime_compile_proc.stderr
        if (out_dir / runtime_obj_name).exists() and runtime_compile_proc.returncode == 0:
            runtime_link_obj = f"+c:\\{runtime_obj_name}"

    link_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\LINK.EXE",
        "e:\\BIN\\LINK.EXE",
        f"c:\\{obj_name}{runtime_link_obj},c:\\{exe_name},c:\\{map_name},E:\\LIB\\{memory_model.runtime_library};",
    ]
    link_proc = _run(link_cmd, timeout=120)

    map_path = out_dir / map_name
    map_text = ""
    if map_path.exists():
        try:
            map_text = map_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            map_text = ""
    link_diagnostics = "\n".join((link_proc.stdout, link_proc.stderr, map_text))
    link_failed = "error L" in link_diagnostics or "unresolved external" in link_diagnostics.lower()
    built = (out_dir / exe_name).exists() and not link_failed
    return (
        built,
        "\n".join(item for item in (compile_proc.stdout, runtime_compile_stdout) if item),
        "\n".join(item for item in (compile_proc.stderr, runtime_compile_stderr) if item),
        link_proc.stdout,
        link_proc.stderr,
    )


def _compile_and_link(
    source_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc6_root: Path,
    obj_name: str,
    exe_name: str,
    map_name: str,
    cod_name: str | None = None,
    runtime_support: bool = False,
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
    gp_runtime_abi: GPRegisterRuntimeABI8616 = DEFAULT_GP_RUNTIME_ABI_8616,
) -> tuple[bool, str, str, str, str]:
    """Run one complete compiler/linker transaction without cross-worker overlap."""
    with msc6_toolchain_lock(msc6_root):
        return _compile_and_link_unlocked(
            source_path,
            out_dir,
            kvikdos=kvikdos,
            msc6_root=msc6_root,
            obj_name=obj_name,
            exe_name=exe_name,
            map_name=map_name,
            cod_name=cod_name,
            runtime_support=runtime_support,
            memory_model=memory_model,
            gp_runtime_abi=gp_runtime_abi,
        )


def _run_example(
    exe_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    timeout: int = 30,
) -> tuple[bool, int | None, str, str]:
    cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--prog=" + f"c:\\{exe_path.name}",
        f"c:\\{exe_path.name}",
    ]
    try:
        proc = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as ex:
        stdout_data = ex.stdout.decode("utf-8", errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        stderr_data = ex.stderr.decode("utf-8", errors="replace") if isinstance(ex.stderr, bytes) else (ex.stderr or "")
        return False, None, stdout_data, stderr_data + "\nruntime timeout\n"
    return proc.returncode == 0, proc.returncode, proc.stdout, proc.stderr


def _pick_main_proc_candidates_from_cod(
    cod_path: Path | None,
) -> list[tuple[str, str | None, int | None]]:
    if cod_path is None or not cod_path.is_file():
        return []
    proc_re = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+PROC\s+(NEAR|FAR)\b",
        re.IGNORECASE,
    )
    proc_addr_re = re.compile(r"^\s*\*\*\*\s+([0-9A-Fa-f]+)\s+")
    public_re = re.compile(r"^\s*PUBLIC\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)
    proc_kinds: dict[str, set[str]] = {}
    proc_addrs: dict[str, int] = {}
    public_names: set[str] = set()
    current_proc: str | None = None
    try:
        for line in cod_path.read_text(encoding="utf-8", errors="replace").splitlines():
            current_proc = _scan_cod_candidate_line(
                line, proc_re, proc_addr_re, public_re, proc_kinds, proc_addrs, public_names, current_proc
            )
    except Exception:
        return []
    for candidate in DECOMPILE_MAIN_NAMES:
        if candidate in proc_kinds and (not public_names or candidate in public_names):
            selected_kinds = sorted(proc_kinds[candidate])
            selected: list[tuple[str, str | None, int | None]] = [(candidate, selected_kinds[0], proc_addrs.get(candidate))]
            selected.extend(
                (candidate, kind, proc_addrs.get(candidate)) for kind in selected_kinds[1:]
            )
            return selected
    if proc_kinds:
        name, candidate_kinds = next(iter(sorted(proc_kinds.items())))
        first = next(iter(sorted(candidate_kinds)))
        return [(name, first, proc_addrs.get(name))]
    return []


def _scan_cod_candidate_line(
    line: str,
    proc_re: re.Pattern[str],
    proc_addr_re: re.Pattern[str],
    public_re: re.Pattern[str],
    proc_kinds: dict[str, set[str]],
    proc_addrs: dict[str, int],
    public_names: set[str],
    current_proc: str | None,
) -> str | None:
    """Apply one COD line to the proc-kind/address/public collections."""
    proc_match = proc_re.match(line)
    if proc_match is not None:
        name = proc_match.group(1)
        kind = proc_match.group(2).upper()
        proc_kinds.setdefault(name, set()).add(kind)
        return name
    if current_proc is not None and current_proc not in proc_addrs:
        addr_match = proc_addr_re.match(line)
        if addr_match is not None:
            proc_addrs[current_proc] = int(addr_match.group(1), 16)
            current_proc = None
    public_match = public_re.match(line)
    if public_match is not None:
        public_names.add(public_match.group(1))
    return current_proc


def _resolve_main_candidates_from_metadata(
    exe_path: Path,
    cod_path: Path | None,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    sidecar_labels = _lookup_sidecar_code_labels(exe_path)
    for candidate in DECOMPILE_MAIN_NAMES:
        candidate_lower = candidate.lower()
        mapped_addr = sidecar_labels.get(candidate_lower)
        if mapped_addr is None:
            continue
        key = ("sidecar", int(mapped_addr))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "addr",
                "source": "sidecar_labels",
                "name": candidate_lower,
                "value": int(mapped_addr),
            }
        )

    if cod_path is not None and cod_path.is_file():
        candidates.extend(_cod_main_candidates(exe_path, cod_path, seen))

    return candidates


def _resolve_map_path(exe_path: Path) -> Path | None:
    """Return the companion MAP file for the executable, if present."""
    map_path_candidate = exe_path.with_suffix(".MAP")
    if map_path_candidate.exists():
        return map_path_candidate
    alt_map_path = exe_path.with_suffix(".map")
    return alt_map_path if alt_map_path.exists() else None


def _cod_main_candidates(
    exe_path: Path,
    cod_path: Path,
    seen: set[tuple[str, int]],
) -> list[dict[str, object]]:
    """Collect main-proc candidates proven by the COD listing and MAP file."""
    candidates: list[dict[str, object]] = []
    proc_candidates = _pick_main_proc_candidates_from_cod(cod_path)
    map_path = _resolve_map_path(exe_path)
    for candidate_name, candidate_kind, candidate_addr in proc_candidates:
        if candidate_name is None:
            continue
        mapped_addr = None
        if candidate_addr is not None:
            mapped_addr = _resolve_cod_offset_to_exe_addr(
                candidate_addr,
                map_path,
                proc_name=candidate_name,
            )
        if mapped_addr is None:
            continue
        assert candidate_addr is not None
        key = ("cod", int(mapped_addr))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "proc",
                "source": "cod",
                "name": candidate_name,
                "proc_kind": candidate_kind,
                "value": int(mapped_addr),
                "cod_offset": int(candidate_addr),
            }
        )
    return candidates


def _read_map_obj_base_offset(map_path: Path) -> tuple[int | None, dict[int, int], dict[str, int]]:
    entry_off = None
    code_starts: dict[int, int] = {}
    if not map_path.exists():
        return None, code_starts, {}

    prog_re = re.compile(r"Program entry point at ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{1,4})", re.IGNORECASE)
    seg_re = re.compile(
        r"^\s*([0-9A-Fa-f]+)H\s+[0-9A-Fa-f]+H\s+[0-9A-Fa-f]+H\s+([A-Za-z_][\w$?@]*)\s+([A-Za-z]+)\s*$",
        re.IGNORECASE,
    )
    publics_re = re.compile(r"^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([A-Za-z_$?@][\w$?@]*)\s*$", re.IGNORECASE)
    public_name_to_addr: dict[str, int] = {}

    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if entry_off is None:
            m_entry = prog_re.search(stripped)
            if m_entry is not None:
                entry_seg = int(m_entry.group(1), 16)
                entry_off = (entry_seg << 4) + int(m_entry.group(2), 16)
                continue
        match = seg_re.match(stripped)
        if match is not None:
            cls = match.group(3).upper()
            if cls == "CODE":
                code_start = int(match.group(1), 16)
                code_starts[code_start] = code_start
            continue
        public_match = publics_re.match(stripped)
        if public_match is not None:
            public_seg = int(public_match.group(1), 16)
            public_off = int(public_match.group(2), 16)
            symbol = public_match.group(3)
            public_name_to_addr[symbol.lower()] = (public_seg << 4) + public_off
            public_name_to_addr.setdefault(symbol.lstrip("_").lower(), (public_seg << 4) + public_off)

    return entry_off, code_starts, public_name_to_addr


def _resolve_cod_offset_to_exe_addr(
    cod_offset: int,
    map_path: Path | None,
    proc_name: str | None = None,
) -> int | None:
    if cod_offset < 0:
        return None

    if map_path is not None and map_path.exists():
        entry_off, code_starts, public_addrs = _read_map_obj_base_offset(map_path)
        if proc_name is not None:
            cod_symbol = proc_name.lower()
            for candidate in (cod_symbol, cod_symbol.lstrip("_")):
                if candidate in {"", "_"}:
                    continue
                if candidate in public_addrs:
                    return 0x10000 + public_addrs[candidate]
            # symbol not found; continue to offset heuristic fallback.

        if code_starts:
            code_base = min(code_starts.keys())
            # Heuristic for MS DOS real-mode objects: default load base is 0x10000.
            # Use code segment start when map addresses are in non-zero offset space.
            if entry_off is None:
                return 0x10000 + code_base + cod_offset
            # Keep compatibility with common map formats where segment offsets are
            # still relative to image origin, while runtime is linked at 0x10000.
            return 0x10000 + code_base + cod_offset

    # Last-resort fallback: legacy object/procedure offsets are often 0-based
    # relative to linked image + image base.
    return 0x10000 + cod_offset


def _is_proc_selection_failure(stderr_text: str) -> bool:
    return "did not find" in stderr_text and "PROC" in stderr_text


def _parse_decompile_profile(stderr_text: str) -> dict[str, object]:
    """Parse selected-result status separately from failed recovery attempts."""
    profile: dict[str, object] = {
        "functions_queued": None,
        "functions_selected": None,
        "function_times": [],
        "stage_times": [],
        "slow_passes": [],
        "decompiled_count": None,
        "attempted_count": None,
        "attempted_total": None,
        "timed_out_functions": 0,
        "tail_failures": 0,
        "attempt_tail_failures": 0,
        "timeout": read_terminal_status(stderr_text) is CliTerminalStatus.TIMEOUT,
        "wall_seconds": 0.0,
        "asm_fallback": False,
        "tail_validation_status": None,
        "tail_validation_uncollected": False,
        "tail_validation_changed": False,
        "validation_state": [],
        "failed_attempt_validation_state": [],
    }
    for line in stderr_text.splitlines():
        if _profile_count_line(line, profile):
            continue
        if _profile_stage_time_line(line, profile):
            continue
        if _profile_tail_status_line(line, profile):
            continue
        _profile_flag_line(line, profile)
    if profile.get("tail_validation_status") in {
        HarnessTailValidationState.PASSED,
        HarnessTailValidationState.CLEAN,
    }:
        # A focused decompile can reject an initial direct/postprocess attempt,
        # then emit a validated fallback in the same process. The final whole-tail
        # summary is the acceptance boundary for this harness profile.
        profile["tail_validation_changed"] = False
        profile["tail_validation_uncollected"] = False
        profile["tail_failures"] = 0
    return profile


def _profile_count_line(line: str, profile: dict[str, object]) -> bool:
    """Apply summary/count lines to the decompile profile; return True on match."""
    queue_match = re.search(r"functions queued for decompilation:\s*(\d+)", line)
    if queue_match is not None:
        profile["functions_queued"] = int(queue_match.group(1))
        return True
    selected_match = re.search(r"selected\s+(\d+)\s+function\(s\)\s+for display", line)
    if selected_match is not None:
        profile["functions_selected"] = int(selected_match.group(1))
        return True
    decomp_match = re.search(r"summary: decompiled (\d+)/(\d+) shown functions", line)
    if decomp_match is not None:
        profile["decompiled_count"] = {
            "success": int(decomp_match.group(1)),
            "shown": int(decomp_match.group(2)),
        }
        return True
    attempted_match = re.search(r"summary: decompilation attempted for (\d+)/(\d+) displayed function\(s\)", line)
    if attempted_match is not None:
        profile["attempted_count"] = int(attempted_match.group(1))
        profile["attempted_total"] = int(attempted_match.group(2))
        return True
    timed_out_match = re.search(r"summary: (\d+) discovered function\(s\) timed out during decompilation", line)
    if timed_out_match is not None:
        profile["timed_out_functions"] = int(timed_out_match.group(1))
        return True
    return False


def _profile_stage_time_line(line: str, profile: dict[str, object]) -> bool:
    """Apply timing lines (per-function, pass, stage) to the profile."""
    time_match = re.search(r"decompilation time for\s+(0x[0-9a-fA-F]+)\s+([^:]+):\s*([0-9]+(?:\.[0-9]+)?)s", line)
    if time_match is not None:
        function_times = cast(list[dict[str, object]], profile["function_times"])
        function_times.append(
            {
                "addr": time_match.group(1),
                "name": time_match.group(2).strip(),
                "seconds": float(time_match.group(3)),
            }
        )
        return True
    pass_match = re.search(r"(?:structuring|postprocess) pass: ([^\s]+) \(\+([0-9]+(?:\.[0-9]+)?)s\)", line)
    if pass_match is not None:
        seconds = float(pass_match.group(2))
        _append_stage_time(profile, "post_or_struct", pass_match.group(1), seconds)
        return True
    stage_match = re.search(r"stage-time: ([^\s]+) elapsed=([0-9]+(?:\.[0-9]+)?)s", line)
    if stage_match is not None:
        _append_stage_time(profile, "stage_time", stage_match.group(1), float(stage_match.group(2)))
        return True
    return False


def _append_stage_time(profile: dict[str, object], scope: str, name: str, seconds: float) -> None:
    """Record one stage timing and flag slow passes."""
    stage_times = cast(list[dict[str, object]], profile["stage_times"])
    stage_times.append({"scope": scope, "name": name, "seconds": seconds})
    if seconds > DECOMPILE_SLOW_PASS_SECONDS:
        slow_passes = cast(list[dict[str, object]], profile["slow_passes"])
        slow_passes.append({"scope": scope, "name": name, "seconds": seconds})


def _profile_tail_status_line(line: str, profile: dict[str, object]) -> bool:
    """Apply the whole-tail validation status line to the profile."""
    tail_match = re.search(r"\[tail-validation\] whole-tail validation (passed|clean|failed|uncollected)", line, re.IGNORECASE)
    if tail_match is None:
        return False
    status = HarnessTailValidationState(tail_match.group(1).lower())
    profile["tail_validation_status"] = status
    if status is HarnessTailValidationState.UNCOLLECTED:
        profile["tail_validation_uncollected"] = True
    if status is HarnessTailValidationState.FAILED:
        profile["tail_validation_changed"] = True
    return True


def _profile_flag_line(line: str, profile: dict[str, object]) -> None:
    """Apply severity/asm-fallback/failure-family flags to the profile."""
    if re.search(r"\[tail-validation\] severity=changed", line) is not None:
        profile["tail_validation_changed"] = True
    if re.search(r"\[tail-validation\] severity=uncollected", line) is not None:
        profile["tail_validation_uncollected"] = True
    if re.search(r"== asm fallback ==", line) is not None:
        profile["asm_fallback"] = True
    if "failure family:" in line:
        _profile_failure_family_line(line, profile)
        return
    attempt_validation_match = re.search(r"attempt=[^*]*\bvalidation=([a-z_]+)", line)
    if attempt_validation_match is not None and isinstance(profile.get("validation_state"), list):
        validation_state = attempt_validation_match.group(1).lower()
        states = profile["validation_state"]
        assert isinstance(states, list)
        if validation_state not in states:
            states.append(validation_state)


def _profile_failure_family_line(line: str, profile: dict[str, object]) -> None:
    """Record failure-family validation states and tail-failure counters."""
    family_failed = "status=ok" not in line
    validation_match = re.search(r"validation=([a-z_]+)", line)
    if validation_match is not None and isinstance(profile.get("failed_attempt_validation_state"), list):
        validation_state = validation_match.group(1).lower()
        states = profile["failed_attempt_validation_state"]
        assert isinstance(states, list)
        if validation_state not in states:
            states.append(validation_state)
        if validation_state in {"failed", "changed", "uncollected"}:
            family_failed = True
    if family_failed:
        attempt_failures = profile["attempt_tail_failures"]
        profile["attempt_tail_failures"] = (attempt_failures if isinstance(attempt_failures, int) else 0) + 1
        profile["tail_failures"] = profile["attempt_tail_failures"]


def _decompile_profile_text(stdout_text: str, stderr_text: str) -> str:
    return f"{stderr_text}\n{stdout_text}"


def _profile_validation_states(
    profile: dict[str, object],
    *,
    field: str = "validation_state",
) -> frozenset[HarnessValidationState]:
    """Return recognized typed validation states from one profile field."""
    raw_states = profile.get(field)
    if not isinstance(raw_states, list):
        return frozenset()
    states: set[HarnessValidationState] = set()
    for raw_state in raw_states:
        if not isinstance(raw_state, str):
            continue
        try:
            states.add(HarnessValidationState(raw_state))
        except ValueError:
            continue
    return frozenset(states)


def _is_decompile_output_acceptable(
    stdout_text: str,
    stderr_text: str,
    profile: dict[str, object],
) -> tuple[bool, HarnessAcceptanceReason | None]:
    """Require affirmative whole-tail validation, retaining specific refusal reasons."""
    profile_reason = _profile_refusal_reason(profile)
    if profile_reason is not None:
        return False, profile_reason

    tail_status = profile.get("tail_validation_status")
    final_output_accepted = profile.get("returncode") == 0 and tail_status in {
        HarnessTailValidationState.PASSED,
        HarnessTailValidationState.CLEAN,
    }

    if not final_output_accepted:
        state_reason = _validation_state_refusal_reason(profile)
        if state_reason is not None:
            return False, state_reason

    combined_reason = _combined_output_refusal_reason(stdout_text, stderr_text, final_output_accepted, tail_status)
    if combined_reason is not None:
        return False, combined_reason
    if tail_status not in {HarnessTailValidationState.PASSED, HarnessTailValidationState.CLEAN}:
        return False, HarnessAcceptanceReason.TAIL_VALIDATION_UNCOLLECTED
    return True, None


def _profile_refusal_reason(profile: dict[str, object]) -> HarnessAcceptanceReason | None:
    """Return the refusal reason proven by typed profile fields."""
    if profile.get("timeout"):
        return HarnessAcceptanceReason.TIMEOUT
    tail_status = profile.get("tail_validation_status")
    if tail_status is HarnessTailValidationState.FAILED:
        return HarnessAcceptanceReason.TAIL_VALIDATION_FAILED
    if tail_status is HarnessTailValidationState.UNCOLLECTED:
        return HarnessAcceptanceReason.TAIL_VALIDATION_UNCOLLECTED
    if profile.get("tail_validation_changed"):
        return HarnessAcceptanceReason.TAIL_VALIDATION_CHANGED
    if profile.get("asm_fallback"):
        return HarnessAcceptanceReason.ASM_FALLBACK
    return None


def _validation_state_refusal_reason(profile: dict[str, object]) -> HarnessAcceptanceReason | None:
    """Return the refusal reason from collected per-attempt validation states."""
    validation_states = _profile_validation_states(profile) | _profile_validation_states(
        profile,
        field="failed_attempt_validation_state",
    )
    if HarnessValidationState.FAILED in validation_states:
        return HarnessAcceptanceReason.VALIDATION_FAILED
    if HarnessValidationState.CHANGED in validation_states:
        return HarnessAcceptanceReason.VALIDATION_CHANGED
    if HarnessValidationState.UNCOLLECTED in validation_states:
        return HarnessAcceptanceReason.VALIDATION_UNCOLLECTED
    return None


def _combined_output_refusal_reason(
    stdout_text: str,
    stderr_text: str,
    final_output_accepted: bool,
    tail_status: object,
) -> HarnessAcceptanceReason | None:
    """Return the refusal reason named in combined stdout/stderr text."""
    combined = f"{stdout_text}\n{stderr_text}".lower()
    if "== asm fallback ==" in combined:
        return HarnessAcceptanceReason.ASM_FALLBACK
    if "decompile timeout" in combined:
        return HarnessAcceptanceReason.TIMEOUT
    if "decompilation validation_failed" in combined and not final_output_accepted:
        return HarnessAcceptanceReason.VALIDATION_FAILED
    if "acceptance-gate detail:" in combined and not final_output_accepted:
        return HarnessAcceptanceReason.ACCEPTANCE_GATE_FAILED
    if "missing source-evidenced" in combined:
        return HarnessAcceptanceReason.SOURCE_EVIDENCE_FAILED
    if "whole-tail validation failed" in combined and tail_status not in {
        HarnessTailValidationState.PASSED,
        HarnessTailValidationState.CLEAN,
    }:
        return HarnessAcceptanceReason.TAIL_VALIDATION_FAILED
    return None


def _decompile_function_with_options(
    exe_path: Path,
    *,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_function_discovery_backend: str,
    decompile_seed_engine: str,
    decompile_rizin_timeout: int,
    decompile_force_rizin_8616: bool,
    decompile_pat_backend: str | None,
    decompile_signature_catalog: Path | None,
    function_name: str,
    proc_kind: str = "NEAR",
    binary_target: BinaryFunctionTarget | None = None,
    artifact_stem: Path | None = None,
) -> tuple[bool, str, str, dict[str, object], str, str]:
    """Recover a fixture function without substituting alternate source C."""
    start = time.perf_counter()
    cmd = [
        _decompile_python_executable(),
        str(decompile_py),
        "--no-alternate-source-c",
        "--timeout",
        str(decompile_timeout),
        "--function-discovery-backend",
        decompile_function_discovery_backend,
        "--seed-engine",
        decompile_seed_engine,
        "--rizin-timeout",
        str(decompile_rizin_timeout),
    ]
    if binary_target is None:
        cmd.extend(["--proc", function_name, "--proc-kind", proc_kind])
    else:
        if binary_target.name != function_name:
            raise ValueError("Binary target label does not match selected fixture function")
        cmd.extend(["--addr", hex(binary_target.address), "--ignore-local-sidecar-hints"])
    cmd.append(str(exe_path))
    if decompile_pat_backend is not None:
        cmd.extend(["--pat-backend", decompile_pat_backend])
    if decompile_signature_catalog is not None:
        cmd.extend(["--signature-catalog", str(decompile_signature_catalog)])

    process_timeout = _focused_decompile_process_timeout(decompile_timeout)
    try:
        proc = _run(
            cmd,
            cwd=REPO_ROOT,
            timeout=process_timeout,
            env=_make_decompile_env(
                decompile_force_rizin_8616,
                trace_label=f"{exe_path.stem}.{function_name}",
            ),
        )
    except subprocess.TimeoutExpired as ex:
        elapsed = time.perf_counter() - start
        stdout_data = ex.stdout.decode("utf-8", errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        stderr_data = ex.stderr.decode("utf-8", errors="replace") if isinstance(ex.stderr, bytes) else (ex.stderr or "")
        timeout_text = stderr_data + "\ndecompile timeout\n"
        profile = _parse_decompile_profile(timeout_text)
        if artifact_stem is not None:
            profile.update(retain_focused_output(artifact_stem, stdout_data, timeout_text))
        profile["timeout"] = True
        profile["acceptance_reason"] = HarnessAcceptanceReason.TIMEOUT.value
        profile["command"] = " ".join(cmd)
        profile["process_timeout_seconds"] = process_timeout
        profile["analysis_timeout_seconds"] = decompile_timeout
        profile["wall_seconds"] = elapsed
        _attach_decompile_quality_profile(profile, stdout_data, function_name=function_name)
        return (
            False,
            stdout_data,
            timeout_text,
            profile,
            " ".join(cmd),
            function_name,
        )
    elapsed = time.perf_counter() - start
    profile = _parse_decompile_profile(_decompile_profile_text(proc.stdout, proc.stderr))
    if artifact_stem is not None:
        profile.update(retain_focused_output(artifact_stem, proc.stdout, proc.stderr))
    profile["returncode"] = proc.returncode
    acceptable, reason = _is_decompile_output_acceptable(proc.stdout, proc.stderr, profile)
    profile_reason = reason.value if reason is not None else None
    if acceptable and proc.returncode != 0:
        profile_reason = FocusedDecompileRetryReason.NONZERO_EXIT.value
        acceptable = False
    profile["acceptance_reason"] = None if acceptable else profile_reason
    profile["process_timeout_seconds"] = process_timeout
    profile["analysis_timeout_seconds"] = decompile_timeout
    profile["wall_seconds"] = elapsed
    _attach_decompile_quality_profile(profile, proc.stdout, function_name=function_name)
    return (
        acceptable and proc.returncode == 0,
        proc.stdout,
        proc.stderr,
        profile,
        " ".join(cmd),
        function_name,
    )


def _build_from_function_decompiles(
    exe_path: Path,
    out_dir: Path,
    *,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_run_timeout: int,
    decompile_function_discovery_backend: str,
    decompile_seed_engine: str,
    decompile_rizin_timeout: int,
    decompile_force_rizin_8616: bool,
    decompile_pat_backend: str | None,
    decompile_signature_catalog: Path | None,
    fallback_functions: tuple[str, ...],
    fallback_harness: str,
    fallback_prefix: str,
    decompile_c_name: str,
    decompile_obj_name: str,
    decompile_exe_name: str,
    decompile_map_name: str,
    kvikdos: Path,
    msc6_root: Path,
    source_contracts: tuple[GeneratedFunctionSourceContract, ...] = (),
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
    fallback_debug: dict[str, object] | None = None,
    binary_targets: tuple[BinaryFunctionTarget, ...] | None = None,
) -> tuple[bool, bool, int | None, str, str, str, str, str, str]:
    """Rebuild selected decompiled functions with the original compiler model."""
    function_bodies: list[str] = []
    function_debug: list[tuple[str, str, str, dict[str, object]]] = []
    if binary_targets is not None and tuple(target.name for target in binary_targets) != fallback_functions:
        raise ValueError("Binary targets must cover every selected function in order")
    targets = {target.name: target for target in binary_targets or ()}
    options = _FunctionDecompileOptions(
        exe_path=exe_path,
        out_dir=out_dir,
        decompile_py=decompile_py,
        decompile_timeout=decompile_timeout,
        decompile_function_discovery_backend=decompile_function_discovery_backend,
        decompile_seed_engine=decompile_seed_engine,
        decompile_rizin_timeout=decompile_rizin_timeout,
        decompile_force_rizin_8616=decompile_force_rizin_8616,
        decompile_pat_backend=decompile_pat_backend,
        decompile_signature_catalog=decompile_signature_catalog,
        memory_model=memory_model,
        decompile_c_name=decompile_c_name,
    )

    batch_bodies = (
        _try_batch_function_decompiles(
            options,
            fallback_functions=fallback_functions,
            binary_targets=binary_targets,
            targets=targets,
            function_debug=function_debug,
        )
        or {}
    )
    if batch_bodies and fallback_debug is not None:
        fallback_debug["batch_used"] = True
    try:
        for function_name in fallback_functions:
            if function_name in batch_bodies:
                function_bodies.append(batch_bodies[function_name])
                continue
            body = _serial_function_body(
                function_name,
                options=options,
                binary_targets=binary_targets,
                targets=targets,
                function_debug=function_debug,
            )
            if body is None:
                return (
                    False,
                    False,
                    None,
                    "",
                    "",
                    "",
                    "",
                    "",
                    json.dumps(function_debug, sort_keys=True),
                )
            function_bodies.append(body)
    finally:
        if fallback_debug is not None:
            fallback_debug["function_debug"] = _json_safe_profile(function_debug)

    source_path = out_dir / decompile_c_name
    harness_bindings = "\n".join(f"#define {target.name} {target.emitted_name}" for target in targets.values())
    source_text = _prepare_decompiled_source_for_c89(
        _build_fallback_source(function_bodies, fallback_harness, prefix=fallback_prefix,
                               harness_bindings=harness_bindings)
    )
    source_path.write_text(source_text, encoding="utf-8")
    numeric_names = {target.name: target.emitted_name for target in targets.values()}
    bound_contracts = tuple(replace(
        contract, function_name=numeric_names.get(contract.function_name, contract.function_name),
        required_returned_call=numeric_names.get(contract.required_returned_call, contract.required_returned_call)
        if contract.required_returned_call is not None else None,
    ) for contract in source_contracts)
    source_contract_results = _evaluate_generated_function_source_contracts(source_text, bound_contracts)
    source_contracts_passed = all(result.passed for result in source_contract_results)
    if fallback_debug is not None:
        fallback_debug["source_contracts"] = [result.to_dict() for result in source_contract_results]
        fallback_debug["source_contracts_passed"] = source_contracts_passed
    if not source_contracts_passed:
        return (
            False,
            False,
            None,
            "",
            "",
            "",
            "",
            "",
            json.dumps([result.to_dict() for result in source_contract_results], sort_keys=True),
        )

    decompiled_exe_path = out_dir / decompile_exe_name
    recompiled_ok, rec_out, rec_err, rel_out, rel_err = _compile_and_link(
        source_path,
        out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        obj_name=decompile_obj_name,
        exe_name=decompile_exe_name,
        map_name=decompile_map_name,
        cod_name=Path(decompile_c_name).with_suffix(".COD").name,
        runtime_support=True,
        memory_model=memory_model,
    )
    run_exit: int | None = None
    decompile_run_stdout = ""
    decompile_run_stderr = ""
    if recompiled_ok and decompiled_exe_path.exists():
        _, run_exit, decompile_run_stdout, decompile_run_stderr = _run_example(
            decompiled_exe_path,
            out_dir,
            kvikdos=kvikdos,
            timeout=decompile_run_timeout,
        )
    return (
        True,
        recompiled_ok,
        run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
    )


@dataclass(frozen=True)
class _FunctionDecompileOptions:
    """Shared serial/batch decompile invocation settings for one harness build."""

    exe_path: Path
    out_dir: Path
    decompile_py: Path
    decompile_timeout: int
    decompile_function_discovery_backend: str
    decompile_seed_engine: str
    decompile_rizin_timeout: int
    decompile_force_rizin_8616: bool
    decompile_pat_backend: str | None
    decompile_signature_catalog: Path | None
    memory_model: MSCMemoryModel
    decompile_c_name: str


def _extract_body_or_retry_reason(
    targets: dict[str, BinaryFunctionTarget],
    out_text: str,
    function_name: str,
) -> tuple[str | None, FocusedDecompileRetryReason | None]:
    """Extract the generated definition, mapping the missing-body case."""
    try:
        target = targets.get(function_name)
        emitted_name = function_name if target is None else target.emitted_name
        return _extract_decompiled_function_definition(out_text, emitted_name), None
    except RuntimeError as ex:
        if "missing generated definition" not in str(ex):
            raise
        return None, FocusedDecompileRetryReason.MISSING_GENERATED_DEFINITION


def _attempt_function_decompile(
    options: _FunctionDecompileOptions,
    function_name: str,
    targets: dict[str, BinaryFunctionTarget],
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> tuple[bool, str, str, dict[str, object], str, str]:
    """Run one serial decompile attempt for a function."""
    return _decompile_function_with_options(
        options.exe_path,
        decompile_py=options.decompile_py,
        decompile_timeout=options.decompile_timeout,
        decompile_function_discovery_backend=options.decompile_function_discovery_backend,
        decompile_seed_engine=options.decompile_seed_engine,
        decompile_rizin_timeout=options.decompile_rizin_timeout,
        decompile_force_rizin_8616=options.decompile_force_rizin_8616,
        decompile_pat_backend=options.decompile_pat_backend,
        decompile_signature_catalog=options.decompile_signature_catalog,
        function_name=function_name,
        proc_kind=options.memory_model.default_procedure_kind,
        binary_target=targets.get(function_name),
        artifact_stem=options.out_dir / f"{function_name}.attempt-{len(function_debug):03d}",
    )


def _try_batch_function_decompiles(
    options: _FunctionDecompileOptions,
    *,
    fallback_functions: tuple[str, ...],
    binary_targets: tuple[BinaryFunctionTarget, ...] | None,
    targets: dict[str, BinaryFunctionTarget],
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> dict[str, str] | None:
    """Retain accepted bodies by target so only failed jobs need serial retry."""
    if os.environ.get("INERTIA_DISABLE_MSC6_BATCH_FALLBACK", "").strip().lower() in {"1", "true", "yes", "on"}:
        return None
    if not options.exe_path.exists():
        return None
    if not DEFAULT_BATCH_DECOMPILE_PROCS.exists():
        return None
    batch_dir = options.out_dir / f"{Path(options.decompile_c_name).stem}.batch"
    cmd = _batch_decompile_command(
        options,
        batch_dir=batch_dir,
        fallback_functions=fallback_functions,
        binary_targets=binary_targets,
    )
    raw_results = _run_batch_decompile_report(
        options,
        cmd,
        batch_dir,
        job_count=len(fallback_functions),
        function_debug=function_debug,
    )
    if raw_results is None:
        return None
    results_by_proc = {str(item.get("proc")): item for item in raw_results if isinstance(item, dict)}
    batch_bodies: dict[str, str] = {}
    for function_name in fallback_functions:
        result = results_by_proc.get(function_name)
        if not isinstance(result, dict):
            function_debug.append(
                (function_name, function_name, " ".join(cmd), {"acceptance_reason": "batch_missing_proc"})
            )
            continue
        body = _accept_batch_result(
            result=result,
            function_name=function_name,
            cmd_text=" ".join(cmd),
            targets=targets,
            binary_targets=binary_targets,
            function_debug=function_debug,
        )
        if body is not None:
            batch_bodies[function_name] = body
    return batch_bodies


def _batch_decompile_command(
    options: _FunctionDecompileOptions,
    *,
    batch_dir: Path,
    fallback_functions: tuple[str, ...],
    binary_targets: tuple[BinaryFunctionTarget, ...] | None,
) -> list[str]:
    """Build the batch-decompile command, writing the jobs file for binary targets."""
    cmd = [
        _decompile_python_executable(),
        str(DEFAULT_BATCH_DECOMPILE_PROCS),
        str(options.exe_path),
        "--out-dir",
        str(batch_dir),
        "--timeout",
        str(options.decompile_timeout),
        "--function-discovery-backend",
        options.decompile_function_discovery_backend,
        "--seed-engine",
        options.decompile_seed_engine,
        "--rizin-timeout",
        str(options.decompile_rizin_timeout),
    ]
    if binary_targets is None:
        for function_name in fallback_functions:
            cmd.extend(["--proc", function_name])
        cmd.extend(["--proc-kind", options.memory_model.default_procedure_kind])
    else:
        # Job names only bind artifacts back to the harness. Recovery sees
        # numeric addresses, with the same evidence policy as serial jobs.
        jobs = [
            {
                "name": target.name,
                "binary": str(options.exe_path),
                "addr": target.address,
                "alternate_source_c": False,
                "ignore_local_sidecar_hints": True,
                "timeout": options.decompile_timeout,
                "function_discovery_backend": options.decompile_function_discovery_backend,
                "seed_engine": options.decompile_seed_engine,
                "rizin_timeout": options.decompile_rizin_timeout,
                "pat_backend": options.decompile_pat_backend,
                "signature_catalog": str(options.decompile_signature_catalog)
                if options.decompile_signature_catalog
                else None,
            }
            for target in binary_targets
        ]
        batch_dir.mkdir(parents=True, exist_ok=True)
        job_file = batch_dir / "jobs.json"
        job_file.write_text(json.dumps({"jobs": jobs}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        cmd.extend(["--job-file", str(job_file)])
    if options.decompile_pat_backend is not None:
        cmd.extend(["--pat-backend", options.decompile_pat_backend])
    if options.decompile_signature_catalog is not None:
        cmd.extend(["--signature-catalog", str(options.decompile_signature_catalog)])
    return cmd


def _run_batch_decompile_report(
    options: _FunctionDecompileOptions,
    cmd: list[str],
    batch_dir: Path,
    *,
    job_count: int,
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> list[object] | None:
    """Run the batch job and return its result list, recording failures."""
    timeout = _focused_decompile_process_timeout(options.decompile_timeout) * max(1, job_count)
    try:
        proc = _run(
            cmd,
            cwd=REPO_ROOT,
            timeout=timeout,
            env=_make_decompile_env(options.decompile_force_rizin_8616, trace_label=f"{options.exe_path.stem}.batch"),
        )
    except subprocess.TimeoutExpired:
        timeout_profile = {
            "acceptance_reason": HarnessAcceptanceReason.TIMEOUT.value,
            "timeout": True,
            "process_timeout_seconds": timeout,
        }
        function_debug.append(("<batch>", "<batch>", " ".join(cmd), timeout_profile))
        return None
    report_path = batch_dir / "batch_report.json"
    if not report_path.exists():
        function_debug.append(
            (
                "<batch>",
                "<batch>",
                " ".join(cmd),
                {
                    "acceptance_reason": "batch_failed",
                    "returncode": proc.returncode,
                    "stdout": proc.stdout[-2000:],
                    "stderr": proc.stderr[-2000:],
                },
            )
        )
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as ex:
        function_debug.append(
            ("<batch>", "<batch>", " ".join(cmd), {"acceptance_reason": "batch_report_invalid", "error": str(ex)})
        )
        return None
    raw_results = report.get("results") if isinstance(report, dict) else None
    if not isinstance(raw_results, list):
        function_debug.append(("<batch>", "<batch>", " ".join(cmd), {"acceptance_reason": "batch_report_missing"}))
        return None
    return raw_results


def _accept_batch_result(
    *,
    result: dict[str, object],
    function_name: str,
    cmd_text: str,
    targets: dict[str, BinaryFunctionTarget],
    binary_targets: tuple[BinaryFunctionTarget, ...] | None,
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> str | None:
    """Score one batch result and extract its body when acceptable."""
    stdout_path = Path(str(result.get("stdout_path", "")))
    stderr_path = Path(str(result.get("stderr_path", "")))
    out_text = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
    err_text = stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""
    profile = _parse_decompile_profile(_decompile_profile_text(out_text, err_text))
    profile["batch_attempt"] = True
    profile["returncode"] = result.get("returncode")
    profile["wall_seconds"] = result.get("wall_seconds")
    profile["stdout_path"] = str(stdout_path)
    profile["stderr_path"] = str(stderr_path)
    acceptable, reason = _is_decompile_output_acceptable(out_text, err_text, profile)
    profile_reason = reason.value if reason is not None else None
    if acceptable and result.get("returncode") != 0:
        acceptable = False
        profile_reason = FocusedDecompileRetryReason.NONZERO_EXIT.value
    profile["acceptance_reason"] = None if acceptable else profile_reason
    function_debug.append((function_name, function_name, cmd_text, profile))
    if not acceptable:
        retry_reason = _focused_decompile_retry_reason(profile)
        if retry_reason is not FocusedDecompileRetryReason.NONZERO_EXIT or binary_targets is not None:
            return None
        body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
        if body is None:
            profile["acceptance_reason"] = (
                extract_retry_reason.value if extract_retry_reason is not None else "extract_failed"
            )
            return None
        return body
    body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        profile["acceptance_reason"] = (
            extract_retry_reason.value if extract_retry_reason is not None else "extract_failed"
        )
        return None
    return body


def _serial_function_body(
    function_name: str,
    *,
    options: _FunctionDecompileOptions,
    binary_targets: tuple[BinaryFunctionTarget, ...] | None,
    targets: dict[str, BinaryFunctionTarget],
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> str | None:
    """Run the serial attempt/retry mesh for one function; return its body."""
    ok, out_text, _err_text, profile, _cmd, _name = _attempt_function_decompile(
        options, function_name, targets, function_debug
    )
    function_debug.append((function_name, _name, _cmd, profile))
    if not ok:
        return _serial_retry_body(
            function_name,
            out_text,
            profile,
            options=options,
            binary_targets=binary_targets,
            targets=targets,
            function_debug=function_debug,
        )
    body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        ok, out_text, _err_text, profile, _cmd, _name = _attempt_function_decompile(
            options, function_name, targets, function_debug
        )
        retry_profile = dict(profile)
        retry_profile["retry_attempt"] = 2
        retry_profile["retry_reason"] = extract_retry_reason.value if extract_retry_reason else "extract_failed"
        function_debug.append((function_name, _name, _cmd, retry_profile))
        if ok:
            body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        _record_extract_failure(function_debug, function_name, _name, _cmd, profile, extract_retry_reason)
        return None
    return body


def _serial_retry_body(
    function_name: str,
    out_text: str,
    profile: dict[str, object],
    *,
    options: _FunctionDecompileOptions,
    binary_targets: tuple[BinaryFunctionTarget, ...] | None,
    targets: dict[str, BinaryFunctionTarget],
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> str | None:
    """Drive the retry mesh after a failed first serial attempt."""
    retry_reason = _focused_decompile_retry_reason(profile)
    if retry_reason is FocusedDecompileRetryReason.NONZERO_EXIT and binary_targets is None:
        body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
        if body is not None:
            return body
        retry_reason = extract_retry_reason
    if retry_reason is None:
        return _serial_extract_body(
            function_name,
            out_text,
            profile,
            options=options,
            targets=targets,
            function_debug=function_debug,
        )
    ok, out_text, _err_text, profile, _cmd, _name = _attempt_function_decompile(
        options, function_name, targets, function_debug
    )
    retry_profile = dict(profile)
    retry_profile["retry_attempt"] = 2
    retry_profile["retry_reason"] = retry_reason.value
    function_debug.append((function_name, _name, _cmd, retry_profile))
    if not ok:
        return None
    body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        retry_profile = dict(profile)
        retry_profile["retry_attempt"] = 2
        retry_profile["retry_reason"] = extract_retry_reason.value if extract_retry_reason else "extract_failed"
        ok, out_text, _err_text, profile, _cmd, _name = _attempt_function_decompile(
            options, function_name, targets, function_debug
        )
        function_debug.append((function_name, _name, _cmd, retry_profile))
        if ok:
            body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        _record_extract_failure(function_debug, function_name, _name, _cmd, profile, extract_retry_reason)
        return None
    return body


def _serial_extract_body(
    function_name: str,
    out_text: str,
    profile: dict[str, object],
    *,
    options: _FunctionDecompileOptions,
    targets: dict[str, BinaryFunctionTarget],
    function_debug: list[tuple[str, str, str, dict[str, object]]],
) -> str | None:
    """Extract the body from an accepted attempt, retrying once on failure."""
    body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        ok, out_text, _err_text, profile, _cmd, _name = _attempt_function_decompile(
            options, function_name, targets, function_debug
        )
        retry_profile = dict(profile)
        retry_profile["retry_attempt"] = 2
        retry_profile["retry_reason"] = extract_retry_reason.value if extract_retry_reason else "extract_failed"
        function_debug.append((function_name, _name, _cmd, retry_profile))
        if ok:
            body, extract_retry_reason = _extract_body_or_retry_reason(targets, out_text, function_name)
    if body is None:
        _record_extract_failure(function_debug, function_name, _name, _cmd, profile, extract_retry_reason)
        return None
    return body


def _record_extract_failure(
    function_debug: list[tuple[str, str, str, dict[str, object]]],
    function_name: str,
    name: str,
    cmd: str,
    profile: dict[str, object],
    extract_retry_reason: FocusedDecompileRetryReason | None,
) -> None:
    """Record a final body-extraction failure into the debug log."""
    failed_profile = dict(profile)
    failed_profile["acceptance_reason"] = extract_retry_reason.value if extract_retry_reason else "extract_failed"
    function_debug.append((function_name, name, cmd, failed_profile))



def _extract_profile_summary(profile: dict[str, object]) -> str:
    function_times = profile.get("function_times", [])
    if not isinstance(function_times, list):
        return ""
    if not function_times:
        return ""
    slow = [
        item
        for item in function_times
        if isinstance(item, dict) and item.get("seconds", 0.0) > DECOMPILE_SLOW_FUNCTION_SECONDS
    ]
    slow_passes = profile.get("slow_passes", [])
    if not isinstance(slow_passes, list):
        slow_passes = []
    if not slow and not slow_passes:
        return ""
    slowest = max(
        (item for item in function_times if isinstance(item, dict) and isinstance(item.get("seconds"), (int, float))),
        key=lambda item: float(item["seconds"]),
        default=None,
    )
    if slowest is None:
        return ""
    return json.dumps(
        {
            "slow_functions": slow,
            "slowest": slowest,
            "slow_passes": [
                item for item in slow_passes if isinstance(item, dict) and isinstance(item.get("seconds"), (int, float))
            ],
        },
        sort_keys=True,
    )


def _json_safe_profile(value: object, seen: set[int] | None = None) -> object:
    if seen is None:
        seen = set()
    if isinstance(value, dict):
        obj_id = id(value)
        if obj_id in seen:
            return "<recursive>"
        seen.add(obj_id)
        try:
            return {str(key): _json_safe_profile(item, seen) for key, item in value.items()}
        finally:
            seen.remove(obj_id)
    if isinstance(value, (list, tuple)):
        obj_id = id(value)
        if obj_id in seen:
            return "<recursive>"
        seen.add(obj_id)
        try:
            return [_json_safe_profile(item, seen) for item in value]
        finally:
            seen.remove(obj_id)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _decompile(
    exe_path: Path,
    out_dir: Path,
    *,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_run_timeout: int,
    decompile_mode: str,
    decompile_cod_path: Path | None,
    decompile_max_functions: int,
    decompile_function_discovery_backend: str,
    decompile_seed_engine: str,
    decompile_rizin_timeout: int,
    decompile_force_rizin_8616: bool,
    decompile_ignore_local_sidecar_hints: bool,
    decompile_pat_backend: str | None = None,
    decompile_signature_catalog: Path | None = None,
) -> tuple[bool, Path, Path, float, dict[str, object]]:
    """Run binary recovery; metadata may select targets, never replace bodies."""
    stdout_path = out_dir / f"{exe_path.stem}.dec.txt"
    stderr_path = out_dir / f"{exe_path.stem}.dec.err.txt"
    base_cmd = _decompile_base_cmd(
        decompile_py,
        decompile_timeout=decompile_timeout,
        decompile_function_discovery_backend=decompile_function_discovery_backend,
        decompile_seed_engine=decompile_seed_engine,
        decompile_rizin_timeout=decompile_rizin_timeout,
        decompile_ignore_local_sidecar_hints=decompile_ignore_local_sidecar_hints,
        decompile_pat_backend=decompile_pat_backend,
        decompile_signature_catalog=decompile_signature_catalog,
    )
    profile: dict[str, object] = {
        "decompile_mode": decompile_mode,
        "discovery_backend": decompile_function_discovery_backend,
        "seed_engine": decompile_seed_engine,
        "rizin_timeout": decompile_rizin_timeout,
        "force_rizin_8616": decompile_force_rizin_8616,
        "pat_backend": decompile_pat_backend,
        "signature_catalog": str(decompile_signature_catalog) if decompile_signature_catalog is not None else None,
        "selected": {},
    }
    candidates = _main_mode_candidates(
        exe_path,
        decompile_mode=decompile_mode,
        decompile_cod_path=decompile_cod_path,
        decompile_max_functions=decompile_max_functions,
        profile=profile,
    )

    attempts: list[dict[str, object]] = []
    start = time.perf_counter()
    last_proc: subprocess.CompletedProcess[str] | None = None
    last_profile: dict[str, object] | None = None

    try:
        (
            probe_result,
            last_proc,
            last_profile,
            all_selection_failures,
            saw_decompile_timeout,
        ) = _probe_decompile_candidates(
            candidates,
            base_cmd,
            exe_path,
            decompile_mode=decompile_mode,
            decompile_run_timeout=decompile_run_timeout,
            decompile_timeout=decompile_timeout,
            decompile_max_functions=decompile_max_functions,
            force_rizin=decompile_force_rizin_8616,
            attempts=attempts,
            profile=profile,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            start=start,
        )
        if probe_result is not None:
            return probe_result

        last_candidate = attempts[-1].get("candidate") if attempts else None
        last_candidate_kind = last_candidate.get("kind") if isinstance(last_candidate, dict) else None
        if _needs_max_functions_fallback(
            decompile_mode,
            all_selection_failures=all_selection_failures,
            saw_decompile_timeout=saw_decompile_timeout,
            last_candidate_kind=last_candidate_kind,
            attempts=attempts,
        ):
            (
                fallback_result,
                fallback_proc,
                fallback_profile,
            ) = _run_max_functions_fallback(
                base_cmd,
                exe_path,
                decompile_mode=decompile_mode,
                decompile_run_timeout=decompile_run_timeout,
                decompile_timeout=decompile_timeout,
                decompile_max_functions=decompile_max_functions,
                force_rizin=decompile_force_rizin_8616,
                attempts=attempts,
                profile=profile,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                start=start,
            )
            last_proc = fallback_proc
            last_profile = fallback_profile
            if fallback_result is not None:
                return fallback_result

        return _merge_failed_decompile_run(attempts, last_profile, last_proc, profile, stdout_path, stderr_path, start)
    except subprocess.TimeoutExpired as ex:
        return _timeout_decompile_run(ex, attempts, profile, stdout_path, stderr_path, start)


def _probe_decompile_candidates(
    candidates: list[dict[str, object]],
    base_cmd: list[str],
    exe_path: Path,
    *,
    decompile_mode: str,
    decompile_run_timeout: int,
    decompile_timeout: int,
    decompile_max_functions: int,
    force_rizin: bool,
    attempts: list[dict[str, object]],
    profile: dict[str, object],
    stdout_path: Path,
    stderr_path: Path,
    start: float,
) -> tuple[
    tuple[bool, Path, Path, float, dict[str, object]] | None,
    subprocess.CompletedProcess[str] | None,
    dict[str, object] | None,
    bool,
    bool,
]:
    """Probe candidates in order; return (success, last_proc, last_profile, all_selection_failures, saw_timeout)."""
    all_selection_failures = True
    saw_decompile_timeout = False
    last_proc: subprocess.CompletedProcess[str] | None = None
    last_profile: dict[str, object] | None = None
    for attempt_index, candidate in enumerate(candidates, start=1):
        proc, run_profile, acceptable = _record_decompile_attempt(
            attempts,
            attempt_index,
            base_cmd,
            exe_path,
            candidate,
            decompile_mode=decompile_mode,
            decompile_run_timeout=decompile_run_timeout,
            decompile_timeout=decompile_timeout,
            decompile_max_functions=decompile_max_functions,
            force_rizin=force_rizin,
        )
        last_proc = proc
        if acceptable and proc.returncode == 0:
            elapsed = _accept_decompile_run(
                run_profile, proc, stdout_path, stderr_path, attempts, start, profile
            )
            return (
                True,
                stdout_path,
                stderr_path,
                elapsed,
                run_profile,
            ), last_proc, last_profile, all_selection_failures, saw_decompile_timeout

        if run_profile.get("timeout"):
            saw_decompile_timeout = True
        if not _is_proc_selection_failure(proc.stderr):
            all_selection_failures = False

        if decompile_mode == "main" and attempts:
            if run_profile.get("timeout"):
                # Timeout can be backend-specific; try alternate entrypoint candidate if present.
                continue
            if not all_selection_failures:
                # Real rejection is enough to stop probing this candidate chain.
                break
        last_profile = run_profile
        if decompile_mode != "main":
            break
    return None, last_proc, last_profile, all_selection_failures, saw_decompile_timeout


def _record_decompile_attempt(
    attempts: list[dict[str, object]],
    attempt_index: int,
    base_cmd: list[str],
    exe_path: Path,
    candidate: dict[str, object],
    *,
    decompile_mode: str,
    decompile_run_timeout: int,
    decompile_timeout: int,
    decompile_max_functions: int,
    force_rizin: bool,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object], bool]:
    """Run one candidate and append its attempt record."""
    candidate_cmd = _decompile_candidate_command(base_cmd, exe_path, candidate)
    candidate_attempt: dict[str, object] = {
        "candidate": candidate,
        "command": " ".join(candidate_cmd),
    }
    attempts.append(candidate_attempt)
    proc, run_profile, acceptable = _run_decompile_candidate(
        candidate_cmd,
        candidate,
        timeout=_decompile_candidate_run_timeout(
            candidate,
            decompile_mode=decompile_mode,
            decompile_run_timeout=decompile_run_timeout,
            decompile_timeout=decompile_timeout,
            decompile_max_functions=decompile_max_functions,
        ),
        trace_label=f"{exe_path.stem}.attempt{attempt_index}",
        force_rizin=force_rizin,
    )
    candidate_attempt["returncode"] = proc.returncode
    candidate_attempt["profile"] = run_profile
    return proc, run_profile, acceptable


def _decompile_base_cmd(
    decompile_py: Path,
    *,
    decompile_timeout: int,
    decompile_function_discovery_backend: str,
    decompile_seed_engine: str,
    decompile_rizin_timeout: int,
    decompile_ignore_local_sidecar_hints: bool,
    decompile_pat_backend: str | None,
    decompile_signature_catalog: Path | None,
) -> list[str]:
    """Build the shared decompile command prefix with optional evidence flags."""
    cmd = [
        _decompile_python_executable(),
        str(decompile_py),
        "--no-alternate-source-c",
        "--timeout",
        str(decompile_timeout),
        "--function-discovery-backend",
        decompile_function_discovery_backend,
        "--seed-engine",
        decompile_seed_engine,
        "--rizin-timeout",
        str(decompile_rizin_timeout),
    ]
    if decompile_ignore_local_sidecar_hints:
        cmd.extend(["--ignore-local-sidecar-hints"])
    if decompile_pat_backend is not None:
        cmd.extend(["--pat-backend", decompile_pat_backend])
    if decompile_signature_catalog is not None:
        cmd.extend(["--signature-catalog", str(decompile_signature_catalog)])
    return cmd


def _main_mode_candidates(
    exe_path: Path,
    *,
    decompile_mode: str,
    decompile_cod_path: Path | None,
    decompile_max_functions: int,
    profile: dict[str, object],
) -> list[dict[str, object]]:
    """Select decompile candidates for the requested mode and record the choice."""
    if decompile_mode == "main":
        candidates = _resolve_main_candidates_from_metadata(exe_path, decompile_cod_path)
        if not candidates:
            selected_count = max(1, decompile_max_functions)
            candidates = [
                {
                    "kind": "max-functions",
                    "source": "default",
                    "value_type": "max-functions",
                    "value": selected_count,
                }
            ]
            profile["selected"] = {"kind": "max-functions", "value": selected_count}
        else:
            profile["selected"] = {"kind": "candidates", "candidates": candidates}
        return candidates
    selected_count = max(1, decompile_max_functions) if decompile_max_functions > 0 else 0
    candidates = [
        {
            "kind": "max-functions",
            "source": "command-line",
            "value_type": "max-functions",
            "value": selected_count,
        }
    ]
    profile["selected"] = {"kind": "max-functions", "value": selected_count}
    return candidates


def _decompile_candidate_command(
    base_cmd: list[str],
    exe_path: Path,
    candidate: dict[str, object],
) -> list[str]:
    """Extend the base command with the candidate's selector and executable."""
    cmd_for_candidate = list(base_cmd)
    kind = candidate.get("kind")
    if kind == "addr":
        candidate_addr = candidate.get("value")
        if isinstance(candidate_addr, int):
            cmd_for_candidate.extend(["--addr", f"0x{candidate_addr:x}"])
    elif kind == "proc":
        candidate_name = candidate.get("name")
        candidate_kind = candidate.get("proc_kind")
        candidate_cod_offset = candidate.get("cod_offset")
        if isinstance(candidate_name, str) and candidate_name:
            cmd_for_candidate.extend(["--proc", candidate_name, "--proc-kind", str(candidate_kind or "NEAR")])
        elif isinstance(candidate_cod_offset, int):
            map_path = _resolve_map_path(exe_path)
            mapped_addr = _resolve_cod_offset_to_exe_addr(
                candidate_cod_offset,
                map_path,
                proc_name=None,
            )
            if mapped_addr is not None:
                cmd_for_candidate.extend(["--addr", f"0x{mapped_addr:x}"])
    elif kind == "max-functions":
        candidate_value = candidate.get("value")
        if isinstance(candidate_value, int) and candidate_value > 0:
            cmd_for_candidate.extend(["--max-functions", str(candidate_value)])
    cmd_for_candidate.append(str(exe_path))
    return cmd_for_candidate


def _decompile_candidate_run_timeout(
    candidate: dict[str, object],
    *,
    decompile_mode: str,
    decompile_run_timeout: int,
    decompile_timeout: int,
    decompile_max_functions: int,
) -> int:
    """Scale the process timeout for max-functions candidates."""
    if decompile_mode != "functions":
        return int(decompile_run_timeout)
    count = candidate.get("value") if candidate.get("kind") == "max-functions" else decompile_max_functions
    if not isinstance(count, int) or count <= 0:
        count = max(1, decompile_max_functions)
    setup_budget = 90
    return max(int(decompile_run_timeout), int(decompile_timeout) * int(count) + setup_budget)


def _run_decompile_candidate(
    candidate_cmd: list[str],
    candidate: dict[str, object],
    *,
    timeout: int,
    trace_label: str,
    force_rizin: bool,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object], bool]:
    """Run one candidate command and score its acceptance profile."""
    proc = _run(
        candidate_cmd,
        cwd=REPO_ROOT,
        timeout=timeout,
        env=_make_decompile_env(force_rizin, trace_label=trace_label),
    )
    run_profile = _parse_decompile_profile(_decompile_profile_text(proc.stdout, proc.stderr))
    run_profile["returncode"] = proc.returncode
    acceptable, reason = _is_decompile_output_acceptable(proc.stdout, proc.stderr, run_profile)
    run_profile["acceptance_reason"] = None if acceptable else reason
    run_profile["candidate"] = candidate
    return proc, run_profile, acceptable


def _accept_decompile_run(
    run_profile: dict[str, object],
    proc: subprocess.CompletedProcess[str],
    stdout_path: Path,
    stderr_path: Path,
    attempts: list[dict[str, object]],
    start: float,
    profile: dict[str, object],
) -> float:
    """Finalize an accepted run: stamp the profile and write outputs."""
    elapsed = time.perf_counter() - start
    run_profile["commands_tried"] = attempts
    run_profile["wall_seconds"] = elapsed
    run_profile["selected"] = profile.get("selected", {})
    run_profile["slowest_function_summary"] = _extract_profile_summary(run_profile)
    source_text = _prepare_decompiled_source_for_c89(proc.stdout)
    _attach_decompile_quality_profile(run_profile, source_text)
    stdout_path.write_text(source_text, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    return elapsed


def _needs_max_functions_fallback(
    decompile_mode: str,
    *,
    all_selection_failures: bool,
    saw_decompile_timeout: bool,
    last_candidate_kind: object,
    attempts: list[dict[str, object]],
) -> bool:
    """Gate the fallback max-functions attempt after failed main candidates."""
    return (
        decompile_mode == "main"
        and (all_selection_failures or (saw_decompile_timeout and last_candidate_kind != "max-functions"))
        and bool(attempts)
        and last_candidate_kind != "max-functions"
    )


def _run_max_functions_fallback(
    base_cmd: list[str],
    exe_path: Path,
    *,
    decompile_mode: str,
    decompile_run_timeout: int,
    decompile_timeout: int,
    decompile_max_functions: int,
    force_rizin: bool,
    attempts: list[dict[str, object]],
    profile: dict[str, object],
    stdout_path: Path,
    stderr_path: Path,
    start: float,
) -> tuple[
    tuple[bool, Path, Path, float, dict[str, object]] | None,
    subprocess.CompletedProcess[str] | None,
    dict[str, object] | None,
]:
    """Run the fallback max-functions attempt after failed main candidates."""
    fallback_count = max(1, decompile_max_functions)
    fallback_candidate = {
        "kind": "max-functions",
        "source": "fallback-after-failed-main-candidates",
        "value_type": "max-functions",
        "value": fallback_count,
    }
    fallback_cmd = _decompile_candidate_command(base_cmd, exe_path, fallback_candidate)
    fallback_attempt: dict[str, object] = {
        "candidate": fallback_candidate,
        "command": " ".join(fallback_cmd),
    }
    attempts.append(fallback_attempt)
    proc, run_profile, acceptable = _run_decompile_candidate(
        fallback_cmd,
        fallback_candidate,
        timeout=_decompile_candidate_run_timeout(
            fallback_candidate,
            decompile_mode=decompile_mode,
            decompile_run_timeout=decompile_run_timeout,
            decompile_timeout=decompile_timeout,
            decompile_max_functions=decompile_max_functions,
        ),
        trace_label=f"{exe_path.stem}.attempt{len(attempts)}",
        force_rizin=force_rizin,
    )
    fallback_attempt["returncode"] = proc.returncode
    fallback_attempt["profile"] = run_profile
    if acceptable and proc.returncode == 0:
        elapsed = _accept_decompile_run(
            run_profile, proc, stdout_path, stderr_path, attempts, start, profile
        )
        return (True, stdout_path, stderr_path, elapsed, run_profile), proc, run_profile
    return None, proc, run_profile


def _merge_failed_decompile_run(
    attempts: list[dict[str, object]],
    last_profile: dict[str, object] | None,
    last_proc: subprocess.CompletedProcess[str] | None,
    profile: dict[str, object],
    stdout_path: Path,
    stderr_path: Path,
    start: float,
) -> tuple[bool, Path, Path, float, dict[str, object]]:
    """Merge the last failed attempt's outputs into the run profile."""
    elapsed = time.perf_counter() - start
    profile["commands_tried"] = attempts
    merged_profile = (
        last_profile
        if isinstance(last_profile, dict)
        else _parse_decompile_profile(
            _decompile_profile_text(last_proc.stdout, last_proc.stderr) if last_proc else ""
        )
    )
    merged_profile["commands_tried"] = attempts
    merged_profile["selected"] = profile.get("selected", {})
    merged_profile["wall_seconds"] = elapsed
    merged_profile["slowest_function_summary"] = _extract_profile_summary(merged_profile)
    if merged_profile.get("acceptance_reason") is None and last_proc is not None:
        merged_profile["acceptance_reason"] = "no_acceptable_candidate"
    stdout_text = ""
    stderr_text = ""
    if last_proc is not None:
        stdout_text = _prepare_decompiled_source_for_c89(last_proc.stdout)
        stderr_text = last_proc.stderr
    _attach_decompile_quality_profile(merged_profile, stdout_text)
    stdout_path.write_text(stdout_text, encoding="utf-8")
    stderr_path.write_text(stderr_text, encoding="utf-8")
    return False, stdout_path, stderr_path, elapsed, merged_profile


def _timeout_decompile_run(
    ex: subprocess.TimeoutExpired,
    attempts: list[dict[str, object]],
    profile: dict[str, object],
    stdout_path: Path,
    stderr_path: Path,
    start: float,
) -> tuple[bool, Path, Path, float, dict[str, object]]:
    """Finalize a run that hit the process timeout."""
    elapsed = time.perf_counter() - start
    stdout_data = ex.stdout.decode("utf-8", errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
    stderr_data = ex.stderr.decode("utf-8", errors="replace") if isinstance(ex.stderr, bytes) else (ex.stderr or "")
    timeout_text = stderr_data + "\ndecompile timeout\n"
    merged_profile = _parse_decompile_profile(timeout_text)
    merged_profile["commands_tried"] = attempts
    merged_profile["wall_seconds"] = elapsed
    merged_profile["timeout"] = True
    merged_profile["selected"] = profile.get("selected", {})
    merged_profile["acceptance_reason"] = "timeout"
    stdout_text = _prepare_decompiled_source_for_c89(stdout_data)
    _attach_decompile_quality_profile(merged_profile, stdout_text)
    stdout_path.write_text(stdout_text, encoding="utf-8")
    stderr_path.write_text(timeout_text, encoding="utf-8")
    return False, stdout_path, stderr_path, elapsed, merged_profile



_DecompileValidateResult = tuple[
    bool, Path, Path, bool, bool, int | None, str, str, str, str, str, str, float, int, str
]
_FallbackRebuildResult = tuple[bool, bool, int | None, str, str, str, str, str, str]


@dataclass(frozen=True)
class _DecompileValidateOptions:
    """Shared configuration for the decompile/rebuild/validate lanes."""

    exe_path: Path
    out_dir: Path
    kvikdos: Path
    msc6_root: Path
    decompile_py: Path
    decompile_timeout: int
    decompile_run_timeout: int
    decompile_mode: str
    decompile_cod_path: Path | None
    decompile_max_functions: int
    expected_exit_code: int
    decompile_safe_names: tuple[str, str, str, str] | None
    decompile_function_discovery_backend: str
    decompile_seed_engine: str
    decompile_rizin_timeout: int
    decompile_force_rizin_8616: bool
    decompile_ignore_local_sidecar_hints: bool
    decompile_pat_backend: str | None
    decompile_signature_catalog: Path | None
    decompile_fallback_rebuild: dict[str, object] | None
    memory_model: MSCMemoryModel


def _decompile_and_validate(
    exe_path: Path,
    out_dir: Path,
    *,
    kvikdos: Path,
    msc6_root: Path,
    decompile_py: Path,
    decompile_timeout: int,
    decompile_run_timeout: int,
    decompile_mode: str,
    decompile_cod_path: Path | None,
    decompile_max_functions: int,
    expected_exit_code: int,
    decompile_safe_names: tuple[str, str, str, str] | None = None,
    decompile_function_discovery_backend: str = "auto",
    decompile_seed_engine: str = "auto",
    decompile_rizin_timeout: int = 8,
    decompile_force_rizin_8616: bool = False,
    decompile_ignore_local_sidecar_hints: bool = False,
    decompile_pat_backend: str | None = None,
    decompile_signature_catalog: Path | None = None,
    decompile_fallback_rebuild: dict[str, object] | None = None,
    memory_model: MSCMemoryModel = MSCMemoryModel.SMALL,
) -> _DecompileValidateResult:
    """Validate generated C under the same toolchain model as the original."""
    options = _DecompileValidateOptions(
        exe_path=exe_path,
        out_dir=out_dir,
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        decompile_py=decompile_py,
        decompile_timeout=decompile_timeout,
        decompile_run_timeout=decompile_run_timeout,
        decompile_mode=decompile_mode,
        decompile_cod_path=decompile_cod_path,
        decompile_max_functions=decompile_max_functions,
        expected_exit_code=expected_exit_code,
        decompile_safe_names=decompile_safe_names,
        decompile_function_discovery_backend=decompile_function_discovery_backend,
        decompile_seed_engine=decompile_seed_engine,
        decompile_rizin_timeout=decompile_rizin_timeout,
        decompile_force_rizin_8616=decompile_force_rizin_8616,
        decompile_ignore_local_sidecar_hints=decompile_ignore_local_sidecar_hints,
        decompile_pat_backend=decompile_pat_backend,
        decompile_signature_catalog=decompile_signature_catalog,
        decompile_fallback_rebuild=decompile_fallback_rebuild,
        memory_model=memory_model,
    )
    first = _fallback_first_result(options)
    if first is not None:
        return first

    decompile_ok, dec_out, dec_err, decompile_elapsed, decompile_profile = _decompile(
        exe_path,
        out_dir,
        decompile_py=decompile_py,
        decompile_timeout=decompile_timeout,
        decompile_run_timeout=decompile_run_timeout,
        decompile_mode=decompile_mode,
        decompile_cod_path=decompile_cod_path,
        decompile_max_functions=decompile_max_functions,
        decompile_function_discovery_backend=decompile_function_discovery_backend,
        decompile_seed_engine=decompile_seed_engine,
        decompile_rizin_timeout=decompile_rizin_timeout,
        decompile_force_rizin_8616=decompile_force_rizin_8616,
        decompile_ignore_local_sidecar_hints=decompile_ignore_local_sidecar_hints,
        decompile_pat_backend=decompile_pat_backend,
        decompile_signature_catalog=decompile_signature_catalog,
    )
    if not decompile_ok:
        return _decompile_failure_result(options, dec_out, dec_err, decompile_elapsed, decompile_profile)

    (
        recompiled_ok,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_exit,
        decompile_run_stdout,
        decompile_run_stderr,
    ) = _rebuild_and_run(options, dec_out, decompile_profile)

    (
        decompile_ok,
        recompiled_ok,
        decompile_run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
    ) = _merge_post_rebuild_fallback(
        options,
        decompile_profile,
        decompile_ok=decompile_ok,
        recompiled_ok=recompiled_ok,
        decompile_run_exit=decompile_run_exit,
        rec_out=rec_out,
        rec_err=rec_err,
        rel_out=rel_out,
        rel_err=rel_err,
        decompile_run_stdout=decompile_run_stdout,
        decompile_run_stderr=decompile_run_stderr,
    )

    return (
        decompile_ok,
        dec_out,
        dec_err,
        recompiled_ok,
        decompile_run_exit == expected_exit_code,
        decompile_run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
        decompile_elapsed,
        _selected_function_count(decompile_profile),
        json.dumps(_json_safe_profile(decompile_profile), sort_keys=True),
    )


def _rebuild_names(options: _DecompileValidateOptions) -> tuple[str, str, str, str]:
    """Return the configured safe names or the stem-derived defaults."""
    if options.decompile_safe_names is None:
        stem = options.exe_path.stem.upper()
        return (
            f"{stem}_DECOMPILE.C",
            f"{stem}_DECOMPILE.OBJ",
            f"{stem}_DECOMPILE.EXE",
            f"{stem}_DECOMPILE.MAP",
        )
    return options.decompile_safe_names


def _selected_function_count(profile: dict[str, object]) -> int:
    """Best-effort selected-function count from the decompile profile."""
    for key in ("attempted_total", "attempted_count", "functions_selected"):
        value = profile.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    decompiled_count = profile.get("decompiled_count")
    if isinstance(decompiled_count, dict):
        shown = decompiled_count.get("shown")
        if isinstance(shown, int) and shown >= 0:
            return shown
    return 0


def _try_function_fallback(
    options: _DecompileValidateOptions,
    profile: dict[str, object],
) -> _FallbackRebuildResult | None:
    """Preserve the behavioral harness under the selected recovery policy."""
    if options.decompile_fallback_rebuild is None:
        return None
    fallback_functions = options.decompile_fallback_rebuild.get("functions")
    fallback_harness = options.decompile_fallback_rebuild.get("harness")
    fallback_prefix = options.decompile_fallback_rebuild.get("prefix", "")
    raw_source_contracts = options.decompile_fallback_rebuild.get("source_contracts", ())
    if not isinstance(fallback_functions, tuple) or not isinstance(fallback_harness, str):
        return None
    if not isinstance(fallback_prefix, str):
        return None
    if not isinstance(raw_source_contracts, tuple) or not all(
        isinstance(contract, GeneratedFunctionSourceContract) for contract in raw_source_contracts
    ):
        return None
    source_contracts = cast(tuple[GeneratedFunctionSourceContract, ...], raw_source_contracts)
    decomp_name, obj_name, exe_name, map_name = _rebuild_names(options)
    fallback_debug: dict[str, object] = {}
    binary_targets: tuple[BinaryFunctionTarget, ...] | None = None
    if options.decompile_ignore_local_sidecar_hints:
        binding = bind_function_targets(
            fallback_functions, _lookup_sidecar_code_labels(options.exe_path), prefix=fallback_prefix,
        )
        fallback_debug["target_binding_status"] = binding.status.value
        if binding.status is not TargetBindingStatus.BOUND:
            profile["fallback_rebuild"] = {"attempted": False, **fallback_debug}
            return False, False, None, "", "", "", "", "", json.dumps(fallback_debug)
        binary_targets = binding.targets
        fallback_debug["binary_targets"] = [asdict(target) for target in binary_targets]
    result = _build_from_function_decompiles(
        options.exe_path,
        options.out_dir,
        decompile_py=options.decompile_py,
        decompile_timeout=options.decompile_timeout,
        decompile_run_timeout=options.decompile_run_timeout,
        decompile_function_discovery_backend=options.decompile_function_discovery_backend,
        decompile_seed_engine=options.decompile_seed_engine,
        decompile_rizin_timeout=options.decompile_rizin_timeout,
        decompile_force_rizin_8616=options.decompile_force_rizin_8616,
        decompile_pat_backend=options.decompile_pat_backend,
        decompile_signature_catalog=options.decompile_signature_catalog,
        fallback_functions=fallback_functions,
        fallback_harness=fallback_harness,
        fallback_prefix=fallback_prefix,
        decompile_c_name=decomp_name,
        decompile_obj_name=obj_name,
        decompile_exe_name=exe_name,
        decompile_map_name=map_name,
        kvikdos=options.kvikdos,
        msc6_root=options.msc6_root,
        source_contracts=source_contracts,
        fallback_debug=fallback_debug,
        memory_model=options.memory_model,
        binary_targets=binary_targets,
    )
    profile["fallback_rebuild"] = {
        "attempted": True,
        "functions": list(fallback_functions),
        "decompile_ok": result[0],
        "recompile_ok": result[1],
        "run_exit_code": result[2],
        **fallback_debug,
    }
    return result


def _fallback_first_paths(options: _DecompileValidateOptions) -> tuple[Path, Path]:
    """Artifact paths used by the fallback-first result."""
    decomp_name, _obj_name, _exe_name, _map_name = _rebuild_names(options)
    stdout_path = options.out_dir / decomp_name
    stderr_path = options.out_dir / f"{Path(decomp_name).stem}.dec.err.txt"
    return stdout_path, stderr_path


def _fallback_first_result(
    options: _DecompileValidateOptions,
) -> _DecompileValidateResult | None:
    """Run the configured fallback rebuild before probing the whole binary."""
    fallback_functions = (
        options.decompile_fallback_rebuild.get("functions")
        if isinstance(options.decompile_fallback_rebuild, dict)
        else None
    )
    if not isinstance(fallback_functions, tuple):
        return None
    fallback_profile: dict[str, object] = {
        "selected": {"kind": "fallback-rebuild-first", "functions": list(fallback_functions)},
    }
    fallback_start = time.perf_counter()
    fallback_result = _try_function_fallback(options, fallback_profile)
    fallback_elapsed = time.perf_counter() - fallback_start
    if fallback_result is None:
        return None
    (
        fb_ok,
        fb_recompiled_ok,
        fb_run_exit,
        fb_rec_out,
        fb_rec_err,
        fb_rel_out,
        fb_rel_err,
        fb_run_stdout,
        fb_run_stderr,
    ) = fallback_result
    fallback_profile["wall_seconds"] = fallback_elapsed
    fallback_profile["acceptance_reason"] = None if fb_ok else "fallback_rebuild_failed"
    fallback_profile["slowest_function_summary"] = _extract_profile_summary(fallback_profile)
    stdout_path, stderr_path = _fallback_first_paths(options)
    stderr_path.write_text(
        json.dumps(_json_safe_profile(fallback_profile), sort_keys=True), encoding="utf-8"
    )
    profile_json = json.dumps(_json_safe_profile(fallback_profile), sort_keys=True)
    if fb_ok and fb_recompiled_ok and fb_run_exit == options.expected_exit_code:
        return (
            True,
            stdout_path,
            stderr_path,
            fb_recompiled_ok,
            True,
            fb_run_exit,
            fb_rec_out,
            fb_rec_err,
            fb_rel_out,
            fb_rel_err,
            fb_run_stdout,
            fb_run_stderr,
            fallback_elapsed,
            len(fallback_functions),
            profile_json,
        )
    return (
        False,
        stdout_path,
        stderr_path,
        fb_recompiled_ok,
        fb_run_exit == options.expected_exit_code,
        fb_run_exit,
        fb_rec_out,
        fb_rec_err,
        fb_rel_out,
        fb_rel_err,
        fb_run_stdout,
        fb_run_stderr,
        fallback_elapsed,
        len(fallback_functions),
        profile_json,
    )


def _decompile_failure_result(
    options: _DecompileValidateOptions,
    dec_out: Path,
    dec_err: Path,
    decompile_elapsed: float,
    decompile_profile: dict[str, object],
) -> _DecompileValidateResult:
    """Fold a failed decompile into a fallback rebuild or the empty result."""
    selected_functions = _selected_function_count(decompile_profile)
    fallback_result = _try_function_fallback(options, decompile_profile)
    profile_json = json.dumps(_json_safe_profile(decompile_profile), sort_keys=True)
    if fallback_result is not None:
        (
            fb_ok,
            fb_recompiled_ok,
            fb_run_exit,
            fb_rec_out,
            fb_rec_err,
            fb_rel_out,
            fb_rel_err,
            fb_run_stdout,
            fb_run_stderr,
        ) = fallback_result
        return (
            fb_ok and fb_recompiled_ok and fb_run_exit == options.expected_exit_code,
            dec_out,
            dec_err,
            fb_recompiled_ok,
            fb_run_exit == options.expected_exit_code,
            fb_run_exit,
            fb_rec_out,
            fb_rec_err,
            fb_rel_out,
            fb_rel_err,
            fb_run_stdout,
            fb_run_stderr,
            decompile_elapsed,
            selected_functions,
            profile_json,
        )
    return (
        False,
        dec_out,
        dec_err,
        False,
        False,
        None,
        "",
        "",
        "",
        "",
        "",
        "",
        decompile_elapsed,
        selected_functions,
        profile_json,
    )


def _rebuild_and_run(
    options: _DecompileValidateOptions,
    dec_out: Path,
    decompile_profile: dict[str, object],
) -> tuple[bool, str, str, str, str, int | None, str, str]:
    """Rebind the entrypoint, recompile, link, and run the rebuilt binary."""
    decomp_name, obj_name, exe_name, map_name = _rebuild_names(options)

    decomp_src = options.out_dir / decomp_name
    reexe = options.out_dir / exe_name
    shutil.copy2(dec_out, decomp_src)

    from scripts.msc6_entrypoint import bind_msc6_fixture_entrypoint

    entry = bind_msc6_fixture_entrypoint(
        decomp_src.read_text(encoding="utf-8"),
        main_address=_lookup_sidecar_code_labels(options.exe_path).get("main"),
    )
    decompile_profile["entrypoint_binding"] = {"status": entry.status.value, "symbol": entry.symbol, "detail": entry.detail}
    decomp_src.write_text(entry.source, encoding="utf-8")

    recompiled_ok, rec_out, rec_err, rel_out, rel_err = _compile_and_link(
        decomp_src,
        options.out_dir,
        kvikdos=options.kvikdos,
        msc6_root=options.msc6_root,
        obj_name=obj_name,
        exe_name=exe_name,
        map_name=map_name,
        cod_name=Path(decomp_name).with_suffix(".COD").name,
        runtime_support=True,
        memory_model=options.memory_model,
    )
    decompile_run_exit: int | None = None
    decompile_run_stdout = ""
    decompile_run_stderr = ""
    if recompiled_ok and reexe.exists():
        _, decompile_run_exit, decompile_run_stdout, decompile_run_stderr = _run_example(
            reexe,
            options.out_dir,
            kvikdos=options.kvikdos,
            timeout=options.decompile_run_timeout,
        )
    return (
        recompiled_ok,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_exit,
        decompile_run_stdout,
        decompile_run_stderr,
    )


def _merge_post_rebuild_fallback(
    options: _DecompileValidateOptions,
    decompile_profile: dict[str, object],
    *,
    decompile_ok: bool,
    recompiled_ok: bool,
    decompile_run_exit: int | None,
    rec_out: str,
    rec_err: str,
    rel_out: str,
    rel_err: str,
    decompile_run_stdout: str,
    decompile_run_stderr: str,
) -> tuple[bool, bool, int | None, str, str, str, str, str, str]:
    """Merge a fallback rebuild outcome into the rebuild state when configured."""
    state = (
        decompile_ok,
        recompiled_ok,
        decompile_run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
    )
    if options.decompile_fallback_rebuild is None or (
        recompiled_ok and decompile_run_exit == options.expected_exit_code
    ):
        return state
    fallback_result = _try_function_fallback(options, decompile_profile)
    if fallback_result is None:
        return state
    (
        fb_ok,
        fb_recompiled_ok,
        fb_run_exit,
        fb_rec_out,
        fb_rec_err,
        fb_rel_out,
        fb_rel_err,
        fb_run_stdout,
        fb_run_stderr,
    ) = fallback_result
    if fb_ok:
        recompiled_ok = fb_recompiled_ok
        rec_out = fb_rec_out
        rec_err = fb_rec_err
        rel_out = fb_rel_out
        rel_err = fb_rel_err
        decompile_run_exit = fb_run_exit
        decompile_run_stdout = fb_run_stdout
        decompile_run_stderr = fb_run_stderr
    if not (fb_recompiled_ok and fb_run_exit == options.expected_exit_code):
        decompile_ok = False
    elif fb_ok:
        decompile_ok = True
    else:
        decompile_ok = False
    return (
        decompile_ok,
        recompiled_ok,
        decompile_run_exit,
        rec_out,
        rec_err,
        rel_out,
        rel_err,
        decompile_run_stdout,
        decompile_run_stderr,
    )



_DOS_EXAMPLE_NAMES: dict[str, str] = {
    "compare16": "CMP16.C",
    "simple_control": "SIMPLE.C",
    "medium_structs": "MEDIUM.C",
    "compare32": "COMP32.C",
    "loops_jumps": "LOOPS.C",
    "scalar_types_io": "TYPES.C",
    "pointer_memory": "POINT.C",
    "enum_union": "EUNION.C",
    "function_pointers": "FPTR.C",
    "storage_classes": "STORE.C",
    "sortdemo_patterns": "SORTPAT.C",
}


@dataclass(frozen=True)
class _ExampleBuild:
    """Original build/run outcome for one example source."""

    local_source: Path
    build_ok: bool
    c_out: str
    c_err: str
    l_out: str
    l_err: str
    exe_path: Path
    obj_path: Path
    map_path: Path
    cod_path: Path
    run_ok: bool
    run_exit_code: int | None
    run_stdout: str
    run_stderr: str


@dataclass(frozen=True)
class _ExampleDecompile:
    """Decompile/rebuild outcome for one example source."""

    skipped: bool
    ok: bool
    recompiled_ok: bool
    run_ok: bool
    run_exit_code: int | None
    stdout: Path | None
    stderr: Path | None
    wall_seconds: float
    selected_functions: int
    profile: str
    recompiled_exe: str
    recompiled_obj: str
    recompiled_map: str
    compile_stdout: str
    compile_stderr: str
    link_stdout: str
    link_stderr: str
    run_stdout: str
    run_stderr: str


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the harness command-line parser."""
    ap = argparse.ArgumentParser(description="Build simple/medium MS C 6 examples via kvikdos and try decompilation.")
    ap.add_argument("--examples-dir", type=Path, default=DEFAULT_EXAMPLES_DIR)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    ap.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    ap.add_argument("--memory-model", type=MSCMemoryModel, choices=list(MSCMemoryModel), default=MSCMemoryModel.SMALL)
    ap.add_argument("--decompile-py", type=Path, default=DEFAULT_DECOMPILE)
    ap.add_argument(
        "--skip-constructs",
        type=lambda text: [item.strip() for item in text.split(",") if item.strip()],
        default=list(DEFAULT_DECOMPILE_SKIP),
        help=(f"Comma-separated source stems to skip decompilation for (default: {','.join(DEFAULT_DECOMPILE_SKIP)})"),
    )
    ap.add_argument(
        "--decompile-mode",
        choices=("main", "functions"),
        default="main",
        help="Decompilation mode. 'main' decompiles the main/entry proc when available; 'functions' decompiles the configured count.",
    )
    ap.add_argument(
        "--decompile-max-functions",
        type=int,
        default=DECOMPILE_MAX_FUNCTIONS_DEFAULT,
        help="Maximum number of recovered functions to decompile when mode=functions. 0 means decompile all.",
    )
    ap.add_argument(
        "--decompile-timeout",
        type=int,
        default=DECOMPILE_MAIN_TIMEOUT_SECONDS_DEFAULT,
        help="Per-function decompiler timeout in seconds.",
    )
    ap.add_argument(
        "--decompile-run-timeout",
        type=int,
        default=DECOMPILE_MAIN_RUN_TIMEOUT_SECONDS_DEFAULT,
        help="Wall-clock timeout for one decompile invocation in seconds.",
    )
    ap.add_argument(
        "--only-constructs",
        type=lambda text: [item.strip() for item in text.split(",") if item.strip()],
        default=[],
        help="Comma-separated example stems to run. If provided, only these examples are processed.",
    )
    ap.add_argument(
        "--harvest-success-code",
        type=int,
        default=HARNESS_SUCCESS_EXIT_CODE,
        help="Exit code to return when all checks pass.",
    )
    ap.add_argument(
        "--decompile-function-discovery-backend",
        choices=("auto", "angr", "rizin", "hybrid"),
        default="auto",
        help="Force function discovery backend for harness decompilation.",
    )
    ap.add_argument(
        "--decompile-seed-engine",
        choices=("auto", "angr", "rizin"),
        default="auto",
        help="Seed engine used by discovery backend selection.",
    )
    ap.add_argument(
        "--decompile-rizin-timeout",
        type=int,
        default=8,
        help="Timeout in seconds for rizin discovery/evidence in harness mode.",
    )
    ap.add_argument(
        "--decompile-force-rizin-8616",
        action="store_true",
        help="Force rizin-based discovery even when local sidecar hints are available.",
    )
    ap.add_argument(
        "--decompile-ignore-local-sidecar-hints",
        action="store_true",
        help="Recover from binary addresses only; same-build labels may bind the behavioral harness.",
    )
    ap.add_argument(
        "--decompile-pat-backend",
        choices=("python_regex", "hyperscan"),
        default=None,
        help="Optional override for PAT backend.",
    )
    ap.add_argument(
        "--signature-catalog",
        type=Path,
        default=None,
        help="Optional prebuilt signature catalog path for the decompiler.",
    )
    ap.add_argument(
        "--signature-input",
        action="append",
        type=Path,
        default=[],
        help="Additional .pat/.obj/.lib inputs (or directories) to build a temporary catalog for this run.",
    )
    ap.add_argument(
        "--signature-catalog-output",
        type=Path,
        default=None,
        help="Output path when building a temporary catalog from --signature-input (default: <out-dir>/signature_catalogs/runtime_signature_catalog.pat).",
    )
    ap.add_argument(
        "--signature-cache-dir",
        type=Path,
        default=None,
        help="Cache directory when building a temporary signature catalog.",
    )
    return ap


def _resolve_signature_catalog(args: argparse.Namespace) -> tuple[Path | None, bool]:
    """Resolve the signature catalog/inputs; returns (catalog, ok)."""
    signature_inputs: list[Path] = [path for path in args.signature_input if isinstance(path, Path)]
    raw_signature_catalog = args.signature_catalog
    signature_catalog: Path | None = None
    if isinstance(raw_signature_catalog, Path):
        resolved_signature_catalog: Path = raw_signature_catalog
        if not resolved_signature_catalog.is_absolute():
            resolved_signature_catalog = (REPO_ROOT / resolved_signature_catalog).resolve()
        if signature_inputs:
            signature_inputs = [resolved_signature_catalog, *signature_inputs]
        else:
            signature_catalog = resolved_signature_catalog

    if signature_inputs:
        prepared_catalog = _prepare_signature_catalog(
            signature_inputs=signature_inputs,
            signature_catalog_output=args.signature_catalog_output,
            signature_cache_dir=args.signature_cache_dir,
            build_root=args.out_dir,
            default_catalog_name=DEFAULT_SIGNATURE_CATALOG_NAME,
        )
        if prepared_catalog is None:
            return None, False
        signature_catalog = prepared_catalog
    if signature_catalog is not None and not signature_catalog.exists():
        raise SystemExit(f"signature catalog not found: {signature_catalog}")
    return signature_catalog, True


def _build_example(
    source_path: Path,
    args: argparse.Namespace,
) -> _ExampleBuild:
    """Build the original example with MSC6 and record its execution."""
    dos_name = _DOS_EXAMPLE_NAMES.get(source_path.stem, source_path.name.upper())
    local_source = args.out_dir / dos_name
    shutil.copy2(source_path, local_source)
    build_ok, c_out, c_err, l_out, l_err = _compile_and_link(
        local_source,
        args.out_dir,
        kvikdos=args.kvikdos,
        msc6_root=args.msc6_root,
        obj_name=f"{local_source.stem.upper()}.OBJ",
        exe_name=f"{local_source.stem.upper()}.EXE",
        map_name=f"{local_source.stem.upper()}.MAP",
        cod_name=f"{local_source.stem.upper()}.COD",
        memory_model=args.memory_model,
    )
    exe_path = args.out_dir / f"{local_source.stem.upper()}.EXE"
    obj_path = args.out_dir / f"{local_source.stem.upper()}.OBJ"
    map_path = args.out_dir / f"{local_source.stem.upper()}.MAP"
    cod_path = args.out_dir / f"{local_source.stem.upper()}.COD"

    run_ok = False
    run_exit_code: int | None = None
    run_stdout = ""
    run_stderr = ""
    if build_ok and exe_path.exists():
        _, run_exit_code, run_stdout, run_stderr = _run_example(
            exe_path,
            args.out_dir,
            kvikdos=args.kvikdos,
        )
        run_ok = run_exit_code == args.harvest_success_code

    record_original_execution(
        local_source, memory_model=args.memory_model, build_ok=build_ok,
        expected_exit_code=args.harvest_success_code, returncode=run_exit_code,
        stdout=run_stdout, stderr=run_stderr,
        compile_output=(c_out, c_err), link_output=(l_out, l_err),
    )
    return _ExampleBuild(
        local_source=local_source,
        build_ok=build_ok,
        c_out=c_out,
        c_err=c_err,
        l_out=l_out,
        l_err=l_err,
        exe_path=exe_path,
        obj_path=obj_path,
        map_path=map_path,
        cod_path=cod_path,
        run_ok=run_ok,
        run_exit_code=run_exit_code,
        run_stdout=run_stdout,
        run_stderr=run_stderr,
    )


def _empty_decompile(skipped: bool, stem: str, out_dir: Path) -> _ExampleDecompile:
    """Default decompile outcome when no decompile attempt runs."""
    return _ExampleDecompile(
        skipped=skipped,
        ok=False,
        recompiled_ok=False,
        run_ok=False,
        run_exit_code=None,
        stdout=None,
        stderr=None,
        wall_seconds=0.0,
        selected_functions=0,
        profile="{}",
        recompiled_exe=str(out_dir / f"{stem}_DECOMPILE.EXE"),
        recompiled_obj=str(out_dir / f"{stem}_DECOMPILE.OBJ"),
        recompiled_map=str(out_dir / f"{stem}_DECOMPILE.MAP"),
        compile_stdout="",
        compile_stderr="",
        link_stdout="",
        link_stderr="",
        run_stdout="",
        run_stderr="",
    )


def _decompile_example(
    source_path: Path,
    build: _ExampleBuild,
    args: argparse.Namespace,
    signature_catalog: Path | None,
    decompile_idx: int,
    decompile_skip: set[str],
) -> _ExampleDecompile:
    """Decompile and validate one example when the original run succeeded."""
    skipped = source_path.stem in decompile_skip
    stem = build.local_source.stem.upper()
    if not (build.build_ok and build.run_ok and build.exe_path.exists() and not skipped):
        return _empty_decompile(skipped, stem, args.out_dir)
    decompile_c_name, decompile_obj_name, decompile_exe_name, decompile_map_name = _dos_safe_names(
        stem,
        counter=decompile_idx,
    )
    (
        decompile_ok,
        decompile_stdout,
        decompile_stderr,
        decompile_recompiled_ok,
        decompile_run_ok,
        decompile_run_exit_code,
        decompile_compile_stdout,
        decompile_compile_stderr,
        decompile_link_stdout,
        decompile_link_stderr,
        decompile_run_stdout,
        decompile_run_stderr,
        decompile_wall_seconds,
        decompile_selected_functions,
        decompile_profile,
    ) = _decompile_and_validate(
        build.exe_path,
        args.out_dir,
        kvikdos=args.kvikdos,
        msc6_root=args.msc6_root,
        memory_model=args.memory_model,
        decompile_py=args.decompile_py,
        decompile_timeout=args.decompile_timeout,
        decompile_run_timeout=args.decompile_run_timeout,
        decompile_mode=args.decompile_mode,
        decompile_cod_path=build.cod_path,
        decompile_max_functions=args.decompile_max_functions,
        expected_exit_code=args.harvest_success_code,
        decompile_function_discovery_backend=args.decompile_function_discovery_backend,
        decompile_seed_engine=args.decompile_seed_engine,
        decompile_rizin_timeout=args.decompile_rizin_timeout,
        decompile_force_rizin_8616=args.decompile_force_rizin_8616,
        decompile_ignore_local_sidecar_hints=args.decompile_ignore_local_sidecar_hints,
        decompile_pat_backend=args.decompile_pat_backend,
        decompile_signature_catalog=signature_catalog,
        decompile_fallback_rebuild=FALLBACK_EXAMPLE_REBUILD.get(source_path.stem),
        decompile_safe_names=(
            decompile_c_name,
            decompile_obj_name,
            decompile_exe_name,
            decompile_map_name,
        ),
    )
    return _ExampleDecompile(
        skipped=skipped,
        ok=decompile_ok,
        recompiled_ok=decompile_recompiled_ok,
        run_ok=decompile_run_ok,
        run_exit_code=decompile_run_exit_code,
        stdout=decompile_stdout,
        stderr=decompile_stderr,
        wall_seconds=decompile_wall_seconds,
        selected_functions=decompile_selected_functions,
        profile=decompile_profile,
        recompiled_exe=str(args.out_dir / decompile_exe_name),
        recompiled_obj=str(args.out_dir / decompile_obj_name),
        recompiled_map=str(args.out_dir / decompile_map_name),
        compile_stdout=decompile_compile_stdout,
        compile_stderr=decompile_compile_stderr,
        link_stdout=decompile_link_stdout,
        link_stderr=decompile_link_stderr,
        run_stdout=decompile_run_stdout,
        run_stderr=decompile_run_stderr,
    )


def _process_example_source(
    source_path: Path,
    args: argparse.Namespace,
    signature_catalog: Path | None,
    decompile_idx: int,
    decompile_skip: set[str],
) -> ExampleResult:
    """Build, run, and decompile one example source into a result row."""
    build = _build_example(source_path, args)
    decompile = _decompile_example(
        source_path, build, args, signature_catalog, decompile_idx, decompile_skip
    )
    return ExampleResult(
        name=source_path.stem,
        source=str(build.local_source),
        exe=str(build.exe_path),
        obj=str(build.obj_path),
        map=str(build.map_path),
        cod=str(build.cod_path),
        build_ok=build.build_ok,
        run_ok=build.run_ok,
        run_exit_code=build.run_exit_code,
        run_stdout=build.run_stdout,
        run_stderr=build.run_stderr,
        decompile_skipped=decompile.skipped,
        decompile_ok=decompile.ok,
        decompile_recompiled=not decompile.skipped and build.build_ok and build.run_ok,
        decompile_recompile_ok=decompile.recompiled_ok,
        decompile_run_ok=decompile.run_ok,
        decompile_run_exit_code=decompile.run_exit_code,
        decompile_recompiled_exe=decompile.recompiled_exe,
        decompile_recompiled_obj=decompile.recompiled_obj,
        decompile_recompiled_map=decompile.recompiled_map,
        decompile_compile_stdout=decompile.compile_stdout,
        decompile_compile_stderr=decompile.compile_stderr,
        decompile_link_stdout=decompile.link_stdout,
        decompile_link_stderr=decompile.link_stderr,
        decompile_run_stdout=decompile.run_stdout,
        decompile_run_stderr=decompile.run_stderr,
        compile_stdout=build.c_out,
        compile_stderr=build.c_err,
        link_stdout=build.l_out,
        link_stderr=build.l_err,
        decompile_stdout_path=str(decompile.stdout) if decompile.stdout is not None else None,
        decompile_stderr_path=str(decompile.stderr) if decompile.stderr is not None else None,
        decompile_wall_seconds=decompile.wall_seconds,
        decompile_selected_functions=decompile.selected_functions,
        decompile_profile=decompile.profile,
    )


def _write_report(args: argparse.Namespace, results: list[ExampleResult]) -> None:
    """Write report.json and print the per-example summary lines."""
    report_path = args.out_dir / "report.json"
    report_path.write_text(json.dumps([asdict(item) for item in results], indent=2), encoding="utf-8")
    print(report_path)
    for item in results:
        print(
            f"{item.name}: "
            f"build={'ok' if item.build_ok else 'fail'} "
            f"run={'ok' if item.run_ok else f'fail({item.run_exit_code})'} "
            f"decompile={'skipped' if item.decompile_skipped else ('ok' if item.decompile_ok else 'fail')} "
            f"decomp_time={item.decompile_wall_seconds:.2f}s "
            f"decomp_funcs={item.decompile_selected_functions} "
            f"decompile_profile={item.decompile_profile} "
            f"recompile={'skipped' if item.decompile_skipped else ('ok' if item.decompile_recompile_ok else 'fail')} "
            f"decompile_run={'skipped' if item.decompile_skipped else ('ok' if item.decompile_run_ok else f'fail({item.decompile_run_exit_code})')} "
            f"exe={item.exe}"
        )


def _all_examples_ok(results: list[ExampleResult]) -> bool:
    """Final acceptance gate across all example results."""
    return all(
        item.build_ok
        and item.run_ok
        and (item.decompile_ok or item.decompile_skipped)
        and ((item.decompile_recompile_ok and item.decompile_run_ok) or item.decompile_skipped)
        for item in results
    )


def main() -> int:
    """Run the MS C construct build/decompile/rebuild harness."""
    args = _build_arg_parser().parse_args()
    signature_catalog, catalog_ok = _resolve_signature_catalog(args)
    if not catalog_ok:
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    results: list[ExampleResult] = []
    only_set = set(args.only_constructs)
    decompile_skip = set(args.skip_constructs)
    decompile_idx = 0

    for source_path in sorted(args.examples_dir.glob("*.c")):
        if only_set and source_path.stem not in only_set:
            continue
        decompile_idx += 1
        results.append(
            _process_example_source(
                source_path, args, signature_catalog, decompile_idx, decompile_skip
            )
        )

    _write_report(args, results)
    return 0 if _all_examples_ok(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
