from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from pycparser import c_ast, c_parser
from test_x86_16_scalar_byte_behavior import assert_scalar_byte_add_behavior
from x86_16_timeout_support import scaled_decompile_timeout

from scripts.msc6_runtime_gate_artifacts import (
    MSC6RuntimeGateArtifacts,
    MSC6RuntimeGateInputs,
    load_or_run_msc6_runtime_gate,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CMP16_EXE = REPO_ROOT / "examples" / "build_msc6" / "CMP16.EXE"
CMP32_EXE = REPO_ROOT / "examples" / "build_msc6" / "COMP32.EXE"
FPTR_EXE = REPO_ROOT / "examples" / "build_msc6" / "FPTR.EXE"
SIMPLE_EXE = REPO_ROOT / "examples" / "build_msc6" / "SIMPLE.EXE"
LOOPS_EXE = REPO_ROOT / "examples" / "build_msc6" / "LOOPS.EXE"
POINT_EXE = REPO_ROOT / "examples" / "build_msc6" / "POINT.EXE"
TYPES_EXE = REPO_ROOT / "examples" / "build_msc6" / "TYPES.EXE"
CLI_PATH = REPO_ROOT / "decompile.py"
RUNTIME_GATE_PATH = REPO_ROOT / "scripts" / "verify_msc_example_runtime_gate.py"
KVIKDOS_PATH = Path("/home/xor/kvikdos/kvikdos")
MSC6_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
MSC6_RUNTIME_EXAMPLES = (
    ("simple_control", SIMPLE_EXE),
    ("cmp16", CMP16_EXE),
    ("cmp32", CMP32_EXE),
    ("fptr", FPTR_EXE),
    ("loops_jumps", LOOPS_EXE),
    ("pointer_memory", POINT_EXE),
    ("scalar_types_io", TYPES_EXE),
)
MSC6_RUNTIME_OUTPUT_STEMS = {
    "simple_control": "SIMPLERT",
    "cmp16": "CMP16RT",
    "cmp32": "CMP32RT",
    "fptr": "FPTRRT",
    "loops_jumps": "LOOPSRT",
    "pointer_memory": "POINTRT",
    "scalar_types_io": "TYPESRT",
}
pytestmark = [pytest.mark.xdist_group("msc6-runtime-gate"), pytest.mark.resource_serial]


def _run_decompile_addr(
    addr: str,
    *,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    timeout = scaled_decompile_timeout(timeout)
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--alternate-source-c",
            "--addr",
            addr,
            "--timeout",
            str(timeout),
            str(CMP16_EXE),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout + 30,
        check=False,
    )


def _extract_emitted_function_8616(output: str, function_name: str) -> str:
    emitted = output
    if "/* == c == */" in emitted:
        emitted = emitted.split("/* == c == */", 1)[-1]
    signature_match = None
    for match in re.finditer(rf"(?m)^[^\n;]*\b{re.escape(function_name)}\s*\([^;\n]*\)", emitted):
        suffix = emitted[match.end() : match.end() + 128]
        if "{" in suffix.split(";", 1)[0]:
            signature_match = match
            break
    if signature_match is None:
        return ""
    start = signature_match.start()
    function_text = emitted[start:]
    end = function_text.find("\n}\n")
    return function_text if end < 0 else function_text[: end + 3]


def _normalize_compound_or_assignments_8616(c_text: str) -> str:
    """Normalize equivalent OR-assignment spellings for semantic assertions."""
    return re.sub(r"\b([A-Za-z_]\w*)\s*\|=\s*([^;]+);", r"\1 = \1 | \2;", c_text)


def _c_integer_constant_8616(node: c_ast.Node | None) -> int | None:
    """Return one integer literal value from a parsed generated-C expression."""
    if isinstance(node, c_ast.Constant) and node.type in {"int", "unsigned int"}:
        return int(node.value, 0)
    if isinstance(node, c_ast.UnaryOp) and node.op == "-":
        operand = _c_integer_constant_8616(node.expr)
        return None if operand is None else -operand
    return None


class _Cmp16SemanticVisitor8616(c_ast.NodeVisitor):
    """Collect return constants and relevant call arguments from parsed C."""

    def __init__(self) -> None:
        self.return_values: list[int] = []
        self.calls: list[tuple[str, tuple[int, ...]]] = []

    def visit_Return(self, node: c_ast.Return) -> None:
        """Collect one integer return without depending on decimal/hex spelling."""
        value = _c_integer_constant_8616(node.expr)
        if value is not None:
            self.return_values.append(value)
        self.generic_visit(node)

    def visit_FuncCall(self, node: c_ast.FuncCall) -> None:
        """Collect one relevant direct call and its constant argument values."""
        if isinstance(node.name, c_ast.ID) and node.name.name in {
            "cmp_i16",
            "rel_i16",
            "rel_u16",
            "clamp_u16",
            "in_window_i16",
        }:
            expressions = tuple(node.args.exprs) if isinstance(node.args, c_ast.ExprList) else ()
            values = tuple(_c_integer_constant_8616(expr) for expr in expressions)
            if all(value is not None for value in values):
                self.calls.append((node.name.name, tuple(value for value in values if value is not None)))
        self.generic_visit(node)


def _cmp16_semantic_projection_8616(c_text: str) -> _Cmp16SemanticVisitor8616:
    """Parse one emitted CMP16 function into spelling-independent test facts."""
    syntax_tree = c_parser.CParser().parse(c_text)
    visitor = _Cmp16SemanticVisitor8616()
    visitor.visit(syntax_tree)
    return visitor


def _runtime_decompile_output_8616(
    artifacts: MSC6RuntimeGateArtifacts,
    example_name: str,
    function_name: str,
) -> str:
    """Load one decompile already accepted by the complete runtime gate."""
    result = artifacts.results[example_name]
    assert not isinstance(result, subprocess.TimeoutExpired), str(result)
    assert result is not None
    assert result.returncode == 0, f"{result.stderr}\n{result.stdout}"

    stdout_path = artifacts.output_root / f"{example_name}_runtime_gate" / (
        f"{MSC6_RUNTIME_OUTPUT_STEMS[example_name]}_{function_name}.dec.txt"
    )
    stderr_path = stdout_path.with_name(stdout_path.name.replace(".dec.txt", ".dec.err.txt"))
    assert stdout_path.is_file() and stderr_path.is_file(), (stdout_path, stderr_path)
    return stderr_path.read_text(encoding="utf-8") + stdout_path.read_text(encoding="utf-8")


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
def test_msc6_cmp16_rel_i16_keeps_recovered_signature_and_avoids_implicit_arg_placeholders(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(msc6_runtime_gate_artifacts, "cmp16", "rel_i16")

    emitted_body = _extract_emitted_function_8616(combined, "rel_i16")
    assert emitted_body, combined
    assert re.search(r"\b(?:int|short)\s+rel_i16\((?:int|short)\s+a,\s+(?:int|short)\s+b\)", emitted_body), (
        emitted_body
    )
    assert "unsigned short a" not in emitted_body
    assert "unsigned short b" not in emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert not re.search(r"\b(?:sp|bp)_0\b", emitted_body), emitted_body
    assert not re.search(r"\b(ir|vvar)_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "return" in emitted_body and "return;" not in emitted_body
    assert "mask * 0x100" not in emitted_body
    assert ">> 8" not in emitted_body
    normalized_body = _normalize_compound_or_assignments_8616(emitted_body)
    for fragment in (
        "if (b > a)",
        "mask = mask | 1;",
        "if (b >= a)",
        "mask = mask | 2;",
        "if (b < a)",
        "mask = mask | 4;",
        "if (b <= a)",
        "mask = mask | 8;",
    ):
        assert fragment in normalized_body, emitted_body
    assert "return mask;" in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
def test_msc6_cmp16_main_preserves_all_guarded_return_chain_values() -> None:
    result = _run_decompile_addr("0x101a7")
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted = _extract_emitted_function_8616(combined, "main")
    assert emitted, combined
    emitted_without_source_comments = "\n".join(
        line for line in emitted.splitlines() if not line.lstrip().startswith("///")
    )
    semantics = _cmp16_semantic_projection_8616(emitted_without_source_comments)
    assert semantics.return_values == [*range(1, 14), 255]
    assert "::0x" not in emitted_without_source_comments
    expected_calls = (
        ("cmp_i16", (65534, 5)), ("cmp_i16", (9, 3)), ("cmp_i16", (7, 7)),
        ("rel_i16", (65534, 5)), ("rel_i16", (9, 3)), ("rel_i16", (7, 7)),
        ("rel_u16", (2, 9)), ("rel_u16", (12, 3)), ("rel_u16", (6, 6)),
        ("clamp_u16", (10, 7)), ("clamp_u16", (6, 7)),
        ("in_window_i16", (4, 1, 7)), ("in_window_i16", (9, 1, 7)),
    )
    assert semantics.calls == list(expected_calls)


@pytest.mark.skipif(not SIMPLE_EXE.is_file(), reason="SIMPLE example binary is not available in this workspace.")
def test_msc6_simple_switch_fold_direct_output_uses_source_argument_identity(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "simple_control", "switch_fold"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "switch_fold")
    assert emitted_body, combined
    assert re.search(
        r"\b(?:int|short|unsigned short) switch_fold\((?:int|short|unsigned short) x\)",
        emitted_body,
    )
    assert re.search(r"if \(!(?:\(unsigned short\))?x\)", emitted_body), emitted_body
    assert "return x - 5;" in emitted_body
    assert "return x + 20;" in emitted_body
    assert "return x << 1;" in emitted_body
    assert not re.search(r"\b(?:arg|local)_4\b", emitted_body), emitted_body


@pytest.mark.skipif(not TYPES_EXE.is_file(), reason="TYPES example binary is not available in this workspace.")
def test_msc6_scalar_add_sc_keeps_byte_width_through_cli_regeneration(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
    tmp_path: Path,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "scalar_types_io", "add_sc"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, "add_sc")
    assert emitted_body, combined
    assert re.search(
        r"\b(?:signed |unsigned )?char add_sc\("
        r"(?:signed |unsigned )?char a, (?:signed |unsigned )?char b\)",
        emitted_body,
    ), emitted_body
    assert not re.search(r"\b(?:short|int) add_sc\(", emitted_body), emitted_body
    assert "return b + a;" in emitted_body or "return a + b;" in emitted_body
    # TYPES.COD saves SI/DI; their proven byte locals are not failed recovery.
    assert_scalar_byte_add_behavior(emitted_body, tmp_path)


@pytest.mark.skipif(not TYPES_EXE.is_file(), reason="TYPES example binary is not available in this workspace.")
def test_msc6_scalar_sub_ss_keeps_straight_line_subtraction(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "scalar_types_io", "sub_ss"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "sub_ss")
    assert emitted_body, combined
    assert "return a - b;" in emitted_body
    assert "if (" not in emitted_body
    assert "stack_base" not in emitted_body
    assert not re.search(r"\b(?:ax|ir_[0-9]+|vvar_[0-9]+)\s*=", emitted_body), emitted_body


@pytest.mark.skipif(not TYPES_EXE.is_file(), reason="TYPES example binary is not available in this workspace.")
def test_msc6_scalar_sub_ulong_emits_consistent_wide_signature_without_probe_artifacts(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "scalar_types_io", "sub_ulong"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, "sub_ulong")
    assert emitted_body, combined
    assert re.search(
        r"\b(?:long sub_ulong\(long a, long b\)|unsigned long sub_ulong\(unsigned long a, unsigned long b\))",
        emitted_body,
    )
    assert "return a - b;" in emitted_body
    assert "sub_105ba" not in emitted_body
    assert "aNchkstk" not in emitted_body
    assert "a = &" not in emitted_body
    assert "v2" not in emitted_body
    assert "vvar_2" not in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.parametrize(
    ("function_name", "required_fragments"),
    [
        ("cmp_i16", ("return -1;", "return 1;", "return 0;", "return 2;", " == ")),
        (
            "rel_i16",
                (
                    "if (b > a)",
                    "mask = mask | 1;",
                    "if (b >= a)",
                    "mask = mask | 2;",
                    "if (b < a)",
                    "mask = mask | 4;",
                    "if (b <= a)",
                    "mask = mask | 8;",
                "return mask;",
            ),
        ),
        (
            "rel_u16",
                (
                    "if (b > a)",
                    "mask = mask | 1;",
                    "if (b >= a)",
                    "mask = mask | 2;",
                    "if (b < a)",
                    "mask = mask | 4;",
                    "if (b <= a)",
                    "mask = mask | 8;",
                "return mask;",
            ),
        ),
        ("clamp_u16", ("return value;", "return limit;")),
        ("in_window_i16", ("return 0;", "return 1;")),
    ],
)
def test_msc6_cmp16_all_helper_functions_pass_tail_validation_and_msc_recompile(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
    function_name: str,
    required_fragments: tuple[str, ...],
) -> None:
    combined = _runtime_decompile_output_8616(msc6_runtime_gate_artifacts, "cmp16", function_name)
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined
    assert "MS C 5.1 msc-dos syntax check failed" not in combined

    emitted_body = _extract_emitted_function_8616(combined, function_name)
    assert emitted_body, combined
    assert not re.search(r"\b[A-Za-z_]\w*_2\b", emitted_body), emitted_body
    assert not re.search(r"\barg_[0-9]+\b", emitted_body), emitted_body
    assert not re.search(r"\bs_[0-9A-Fa-f]+\b", emitted_body), emitted_body
    assert "::0x" not in emitted_body
    assert "mask * 0x100" not in emitted_body
    assert ">> 8" not in emitted_body
    normalized_body = _normalize_compound_or_assignments_8616(emitted_body)
    for fragment in required_fragments:
        assert fragment in normalized_body, emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
def test_msc6_fptr_select_and_apply_materializes_branch_function_pointer_targets(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "fptr", "select_and_apply"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "select_and_apply")
    assert emitted_body, combined
    assert re.match(r"unsigned short\s+select_and_apply\s*\(", emitted_body), emitted_body
    assert "if (which)" in emitted_body
    assert "if (value)" not in emitted_body
    assert "fn = inc_one;" in emitted_body
    assert "fn = dec_one;" in emitted_body
    assert "fn = which;" not in emitted_body
    assert "return apply_twice(fn, value);" in emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
@pytest.mark.parametrize(
    ("function_name", "required_fragment"),
    [
        ("inc_one", "return value + 1;"),
        ("dec_one", "return value - 1;"),
    ],
)
def test_msc6_fptr_leaf_functions_materialize_terminal_ax_returns(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
    function_name: str,
    required_fragment: str,
) -> None:
    combined = _runtime_decompile_output_8616(msc6_runtime_gate_artifacts, "fptr", function_name)
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, function_name)
    assert emitted_body, combined
    assert required_fragment in emitted_body
    assert "return;" not in emitted_body


@pytest.mark.skipif(not FPTR_EXE.is_file(), reason="FPTR example binary is not available in this workspace.")
def test_msc6_fptr_apply_twice_consumes_stack_probe_call_artifacts(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(msc6_runtime_gate_artifacts, "fptr", "apply_twice")
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "apply_twice")
    assert emitted_body, combined
    assert "apply_twice(" in emitted_body
    assert "fn" in emitted_body
    assert "value" in emitted_body
    assert "(*fn)(" in emitted_body
    expected_callback_calls = 2
    assert emitted_body.count("fn(value)") == expected_callback_calls
    assert "return value;" in emitted_body
    assert "chkstk" not in emitted_body.lower()
    assert "SEG_U" not in emitted_body
    assert "local_2 =" not in emitted_body
    assert "v2 = fn" not in emitted_body
    assert "v4 =" not in emitted_body


@pytest.mark.skipif(not LOOPS_EXE.is_file(), reason="LOOPS example binary is not available in this workspace.")
def test_msc6_loops_nested_materializes_stack_counter_loop(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "loops_jumps", "nested_loops"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "nested_loops")
    assert emitted_body, combined
    assert "while (i < limit)" in emitted_body
    assert "do" in emitted_body
    assert "continue;" in emitted_body
    assert "break;" in emitted_body
    assert "return total;" in emitted_body
    assert "stack_base" not in emitted_body
    assert "SEG_U" not in emitted_body


@pytest.mark.skipif(not POINT_EXE.is_file(), reason="POINT example binary is not available in this workspace.")
def test_msc6_pointer_swap_preserves_loaded_temp_across_pointer_store(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
) -> None:
    combined = _runtime_decompile_output_8616(
        msc6_runtime_gate_artifacts, "pointer_memory", "swap_ptrs"
    )
    assert "[tail-validation] whole-tail validation clean across 1 functions" in combined

    emitted_body = _extract_emitted_function_8616(combined, "swap_ptrs")
    assert emitted_body, combined
    assert "left[0] = right[0];" in emitted_body
    assert "right[0] = local_2;" in emitted_body or "right[0] = tmp;" in emitted_body
    assert "right[0] = left[0];" not in emitted_body


@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16 example binary is not available in this workspace.")
@pytest.mark.skipif(not KVIKDOS_PATH.is_file(), reason="kvikdos is not available in this workspace.")
@pytest.mark.skipif(not MSC6_ROOT.is_dir(), reason="MS C 6 root is not available in this workspace.")
@pytest.mark.parametrize(("example_name", "exe_path"), MSC6_RUNTIME_EXAMPLES)
def test_msc6_rebuilt_comparison_executable_runs_success_sentinel(
    msc6_runtime_gate_artifacts: MSC6RuntimeGateArtifacts,
    example_name: str,
    exe_path: Path,
) -> None:
    if not exe_path.is_file():
        pytest.skip(f"{example_name} example binary is not available in this workspace.")

    result = msc6_runtime_gate_artifacts.results[example_name]
    assert not isinstance(result, subprocess.TimeoutExpired), str(result)
    assert result is not None
    combined = f"{result.stderr}\n{result.stdout}"
    assert result.returncode == 0, combined
    assert "status=passed" in combined
    assert "run_exit=255" in combined


@pytest.fixture(scope="module")
def msc6_runtime_gate_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
) -> MSC6RuntimeGateArtifacts:
    """Load verified evidence or run each complete runtime gate once."""
    return load_or_run_msc6_runtime_gate(
        MSC6RuntimeGateInputs(
            repo_root=REPO_ROOT,
            cache_root=REPO_ROOT / ".cache" / "pytest" / "msc6-runtime-gate",
            fallback_output_root=tmp_path_factory.mktemp("msc6_runtime_gate"),
            runtime_gate_path=RUNTIME_GATE_PATH,
            kvikdos_path=KVIKDOS_PATH,
            msc6_root=MSC6_ROOT,
            examples=MSC6_RUNTIME_EXAMPLES,
            timeout_seconds=scaled_decompile_timeout(120),
            parallel_example_workers=2,
        )
    )
