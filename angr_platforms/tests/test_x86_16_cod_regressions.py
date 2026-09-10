from __future__ import annotations

import re
import subprocess
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from angr import ailment
from angr.ailment.expression import BinaryOp, Load, StackBaseOffset
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16 import decompiler_postprocess_stage as _postprocess_stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteReturnUseKind8616
from angr_platforms.X86_16.cod_extract import extract_cod_proc_metadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.decompiler_postprocess_stage import _materialize_missing_terminal_ax_return_8616
from angr_platforms.X86_16.decompiler_postprocess_utils import _replace_c_children_8616
from angr_platforms.X86_16.decompiler_return_compat import (
    _infer_x86_16_ax_return_expr_8616,
    _infer_x86_16_c_return_value_from_ax_8616,
    _resolve_codegen_prototype_8616,
    _return_compat_c_result_needs_neutralization_8616,
    _return_compat_function_caller_return_use_8616,
    _return_compat_should_drop_unresolved_c_return_8616,
    apply_x86_16_decompiler_return_compatibility,
    codegen_has_explicit_void_return_8616,
)
from x86_16_timeout_support import scaled_decompile_timeout

import decompile
from inertia_decompiler import cli_c_ast_rewrites as _cli_c_ast_rewrites
from inertia_decompiler import cli_stack_cvars as _cli_stack_cvars
from inertia_decompiler.recompile_check import check_c_recompiles_8616

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
COD_DIR = REPO_ROOT / "cod"
RUNNER_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"

_runner_spec = spec_from_file_location("decompile_cod_dir_test_runner", RUNNER_PATH)
assert _runner_spec is not None and _runner_spec.loader is not None
_runner = module_from_spec(_runner_spec)
sys.modules[_runner_spec.name] = _runner
_runner_spec.loader.exec_module(_runner)


def _run_cod_proc(
    path: Path,
    proc: str,
    *,
    timeout: int = 20,
    scale_timeout: bool = True,
) -> subprocess.CompletedProcess[str]:
    if scale_timeout:
        timeout = scaled_decompile_timeout(timeout)
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--timeout",
            str(timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=max(90, timeout * 6),
        check=False,
    )


def _assert_has_all(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor in text, anchor


def _assert_has_none(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor not in text, anchor


def _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stderr + result.stdout
    if result.returncode == 0:
        return
    if result.returncode == 3:
        assert "timeout" in combined.lower(), combined
        return
    assert result.returncode == 4, combined
    assert (
        "/* direct validation=failed */" in combined
        or "/* == c (partial timeout) == */" in combined
        or "/* == asm fallback == */" in combined
        or "whole-tail validation failed" in combined
    )


def test_cod_timeout_target_is_classified_deterministically():
    start = time.monotonic()
    result = _run_cod_proc(
        COD_DIR / "EGAME11.COD",
        "_drawCockpit",
        timeout=1,
        scale_timeout=False,
    )
    elapsed = time.monotonic() - start

    assert result.returncode == 3, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "Timed out while recovering a function after 1s",
            "Tip: try a larger --timeout for larger binaries.",
        ),
    )
    assert "during x86-16 function recovery" in result.stdout
    assert elapsed < 20, elapsed


@pytest.mark.parametrize(
    "proc_name",
    ("_dos_alloc", "_dos_resize", "_dos_mcbInfo"),
)
def test_cod_runner_hotspots_fall_back_through_scan_safe_classifier(monkeypatch, tmp_path, proc_name: str):
    item = _runner.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name=proc_name,
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        code=b"\x90",
    )
    scan_result = _runner.FunctionScanResult(
        cod_file="DOSFUNC.COD",
        proc_name=proc_name,
        proc_kind="NEAR",
        byte_len=1,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        semantic_family_reason="call-heavy helper path",
        function_count=1,
        decompiled_count=0,
        confidence_status="bounded_recovery",
        confidence_scan_safe_classification="strong",
        stages=[],
    )

    def fake_run(*args, **kwargs):
        stdout_file = kwargs["stdout"]
        stdout_file.write("/* Timed out while recovering a function after 20s. */\n")
        return subprocess.CompletedProcess(args=args[0], returncode=3, stdout="", stderr="")

    monkeypatch.setattr(_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(_runner, "_run_scan_safe_fallback", lambda *_args, **_kwargs: scan_result)

    result = _runner._run_work_item(item, timeout=20, max_memory_mb=1024)
    rendered = _runner._render_result_block(result)

    assert result.exit_kind == "fallback"
    assert result.child_exit_kind == "timeout"
    assert result.scan_safe_result is scan_result
    assert "fallback kind: cfg_only" in rendered
    assert "confidence status: bounded_recovery" in rendered
    assert "confidence scan-safe: strong" in rendered
    assert "child exit kind: timeout" in rendered
    assert "worker process terminated abruptly" not in rendered


def test_cod_biosfunc_clearkeyflags_far_word_store() -> None:
    """Retain discovery and far-store behavior in one real decompilation."""
    result = _run_cod_proc(COD_DIR / "BIOSFUNC.COD", "_bios_clearkeyflags")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _bios_clearkeyflags",
            "SEG_U16(0, 1047) = 0;",
        ),
    )
    assert "whole-tail validation clean" in result.stderr
    _assert_has_none(
        result.stdout,
        (
            "Decompilation empty",
            "inertia_es, 1047",
            "*(1047)",
            "*(1048)",
            "*((unsigned short *)1047)",
            "*((char *)(es * 16 + 1047))",
            "*((char *)(es * 16 + 1048))",
        ),
    )


def test_cod_dos_getfree_call_and_return_recovered() -> None:
    """Retain discovery, declaration and return checks from one CLI run."""
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "whole-tail validation clean" in result.stderr
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getfree",
            "intdos(&rin, &rout);",
            "if (!rout.x.cflag)",
            "ERROR(", "return 0;", "return rout.x.bx;",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "Decompilation empty", "<missing-type>",
            "rin = 72;",
            "rin = 65535;",
            "s_2 = &",
            "s_8 = 28675;",
            "err = 28673;",
            "void _dos_getfree(void)",
        ),
    )
    assert "rout" in result.stdout
    assert "rin" in result.stdout
    assert "S425_rout" not in result.stdout


def test_cod_process_id_source_headers_are_captured():
    get_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_getProcessId")
    set_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_setProcessId")

    assert "uint16 dos_getProcessId(void) {" in get_meta.source_lines
    assert "int dos_setProcessId(const uint16 pid) {" in set_meta.source_lines


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_cod_process_id_helpers_keep_empty_bodies(proc_name: str, header_anchor: str):
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", proc_name)

    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    if result.returncode != 0:
        return
    assert header_anchor in result.stdout
    assert "return;" not in result.stdout


def test_cod_extract_canonicalizes_known_object_names():
    get_meta = extract_cod_proc_metadata(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert "rout" in get_meta.global_names
    assert "S425_rout" not in get_meta.global_names


def test_cod_extract_does_not_treat_indirect_call_width_as_callee(tmp_path):
    cod_path = tmp_path / "FPTR.COD"
    cod_path.write_text(
        "\n".join(
            (
                "apply_twice\tPROC NEAR",
                "    *** 0000 FF 56 04 call WORD PTR [bp+4]",
                "    *** 0003 E8 00 00 call _direct_helper",
                "apply_twice\tENDP",
            )
        ),
        encoding="utf-8",
    )

    metadata = extract_cod_proc_metadata(cod_path, "apply_twice")

    assert metadata.call_names == ("direct_helper",)


def test_cod_extract_preserves_repeated_direct_call_multiplicity(tmp_path):
    cod_path = tmp_path / "REPEATED.COD"
    cod_path.write_text(
        "\n".join(
            (
                "swap_like\tPROC NEAR",
                "    *** 0000 E8 00 00 call _DrawBar",
                "    *** 0003 E8 00 00 call _DrawBar",
                "    *** 0006 E8 00 00 call _DrawTime",
                "swap_like\tENDP",
            )
        ),
        encoding="utf-8",
    )

    metadata = extract_cod_proc_metadata(cod_path, "swap_like")

    assert metadata.call_names == ("DrawBar", "DrawBar", "DrawTime")


def test_preferred_known_helper_signature_decl_prefers_canonical_prefixed_names():
    assert decompile.preferred_known_helper_signature_decl("intdos") == "int _intdos(union REGS *in, union REGS *out);"
    assert decompile.preferred_known_helper_signature_decl("ERROR") == "int _ERROR(const char *fmt, ...);"


def test_cod_strlen_stack_local_copy_is_declared():
    result = _run_cod_proc(COD_DIR / "default" / "STRLEN.COD", "_strlen")

    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    if result.returncode != 0:
        return
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _strlen",
            "n += 1;",
            "return n;",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "if (!(s + 1))",
            "ir_",
            "s_3",
        ),
    )
    assert re.search(r"\bir_\d+\b", result.stdout) is None
    assert "ir_3 = s_3;" not in result.stdout
    assert "ir_4 = s_3;" not in result.stdout
    assert "s_3" not in result.stdout


def test_cod_known_object_catalog_is_exposed():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import angr_platforms.X86_16 as x; print(x.describe_x86_16_cod_known_objects()['names'])",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    _assert_has_all(
        result.stdout,
        (
            "rin",
            "rout",
            "sreg",
            "exeLoadParams",
            "ovlLoadParams",
            "ovlHeader",
            "slotArray",
        ),
    )


def test_cod_overlay_header_known_object_is_pointer_typed():
    spec = known_cod_object_spec("ovlHeader")

    assert spec is not None
    assert spec.type.__class__.__name__ == "SimTypePointer"
    assert getattr(spec.type, "pts_to", None) is not None
    assert getattr(spec.type.pts_to, "name", None) == "OvlHeader"


def test_cod_overlay_function_address_keeps_proven_known_object_bindings():
    result = _run_cod_proc(COD_DIR / "OVERLAY.COD", "_overlay_functionAddress")

    assert result.returncode == 0, result.stderr + result.stdout
    text = result.stdout
    assert "function: 0x1000 _overlay_functionAddress" in text
    assert result.stderr.count("whole-tail validation clean across 1 functions") == 1
    assert re.search(r"long _overlay_functionAddress\([^)]*ovlLoadSegment[^)]*funcNumber[^)]*\)", text)
    assert text.count("SEG_U16(ovlLoadSegment,") >= 2
    assert "36 + (funcNumber << 1)" in text
    assert re.search(r"return\s+[^;]*<< 16\s*\|\s*[^;]+;", text)
    assert "[dbg]" not in text
    assert "== asm fallback ==" not in text
    assert "unassigned-stack-local" not in result.stderr
    assert re.search(r"(?m)^\s*MK_FP\(ovlHeader->code_segment, slotArray\[funcNumber\]\);\s*$", text) is None
    compile_result = check_c_recompiles_8616(text, target="portable-flat")
    assert compile_result.passed, compile_result.stderr


def test_cod_dos_loadoverlay_wrapper_returns_loadprog() -> None:
    """Retain discovery, declaration and forwarding checks from one CLI run."""
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadOverlay")

    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    assert "function: 0x1000 _dos_loadOverlay" in result.stdout
    if result.returncode != 0:
        return
    _assert_has_all(
        result.stdout,
        (
            "file",
            "segment",
        ),
    )
    assert "return" in result.stdout
    _assert_has_none(
        result.stdout,
        (
            "Decompilation empty", "<missing-type>",
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


def test_cod_dos_runprogram_wrapper_returns_loadprog():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_runProgram")

    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    if result.returncode != 0:
        return
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_runProgram",
            "file",
            "cmdline",
        ),
    )
    assert "return" in result.stdout
    _assert_has_none(
        result.stdout,
        (
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


def test_cod_loadprog_preserves_binary_arguments_and_recompiles():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "loadprog", timeout=40)

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    _assert_has_all(
        result.stdout,
        (
            "unsigned short loadprog(unsigned short file, unsigned short segment, unsigned short type, unsigned long cmdline)",
            "exeLoadParams[1] = inertia_eax & 0xffff;",
            "cmdline >> 16 & 0xffff",
            "return err;",
            "return 0;",
        ),
    )
    assert result.stdout.count("return 1;") == 1
    assert result.stdout.count("return err;") == 1
    assert result.stdout.count("return 0;") == 1
    _assert_has_none(
        result.stdout,
        (
            "<missing-type>",
            "arg_c",
            "file_2",
            "type_2",
            "unsigned short loadprog(unsigned short file, unsigned short file_2, unsigned short type, unsigned short type_2)",
            "return err_2;",
        ),
    )
    compile_result = check_c_recompiles_8616(result.stdout, target="portable-flat")
    assert compile_result.passed, compile_result.stderr


def test_cod_openfilewrapper_direct_forwarding() -> None:
    """Check discovery, declarations and forwarding from one identical CLI run."""
    result = _run_cod_proc(COD_DIR / "EGAME2.COD", "_openFileWrapper")
    _assert_cod_proc_succeeded_or_reported_unvalidated_partial(result)
    assert "function: 0x1000 _openFileWrapper" in result.stdout
    if result.returncode != 0:
        return
    _assert_has_all(result.stdout, ("path", "mode"))
    _assert_has_none(
        result.stdout,
        (
            "Decompilation empty", "<missing-type>",
            "s_2 = &",
            "s_4 = mode",
            "s_6 = path",
        ),
    )


def test_cod_dos_getreturncode_returns_value() -> None:
    """Retain discovery and return behavior from one real decompilation."""
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getReturnCode")

    combined = result.stderr + result.stdout
    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "Decompilation empty" not in result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getReturnCode",
            "return rout.h.al;",
        ),
    )


def test_regenerate_codegen_text_falls_back_on_failure():
    class DummyCodegen:
        def __init__(self) -> None:
            self.text = "fallback text"
            self.cfunc = object()

        def regenerate_text(self) -> None:
            raise RecursionError("maximum recursion depth exceeded")

        def render_text(self, _cfunc) -> tuple[str, object]:
            return "rendered text", object()

    text, changed = decompile._regenerate_codegen_text_safely(DummyCodegen(), context="dummy")

    assert text == "rendered text"
    assert changed is False


def test_dedupe_duplicate_local_declarations_text_prefers_annotated_slot():
    c_text = (
        "void _dos_free(unsigned short segment)\n"
        "{\n"
        "    char err;  // [bp-0x6]\n"
        "    char err;  // [bp-0x2] err\n"
        "    return;\n"
        "}\n"
    )

    deduped = decompile._dedupe_duplicate_local_declarations_text(c_text)

    assert "char err_2" not in deduped  # non-annotated duplicate removed, not renamed
    assert "char err;  // [bp-0x2] err" in deduped
    assert deduped.count("char err;") == 1


def test_prune_unused_local_declarations_text_keeps_return_statements():
    c_text = (
        "unsigned short _overlay_load(void)\n"
        "{\n"
        "    unsigned short ovlSegment;\n"
        "    dos_getfree();\n"
        "    return ovlSegment;\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "unsigned short ovlSegment;" in pruned
    assert "return ovlSegment;" in pruned


def test_prune_unused_local_declarations_text_keeps_annotated_declarations():
    c_text = (
        "unsigned short _overlay_load(void)\n"
        "{\n"
        "    unsigned short ovlSegment;  // [bp-0x4] ovlSegment\n"
        "    dos_getfree();\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "unsigned short ovlSegment;  // [bp-0x4] ovlSegment" in pruned


def test_prune_unused_local_declarations_text_drops_unused_stack_bp_placeholder_declaration():
    c_text = (
        "short PercolateUp(int iMaxLevel)\n"
        "{\n"
        "    int stack_bp_m6_b1;  // [bp-0x6]\n"
        "    char s_fffa;\n"
        "    s_fffa = 1;\n"
        "    return s_fffa;\n"
        "}\n"
    )

    pruned = decompile._prune_unused_local_declarations_text(c_text)

    assert "int stack_bp_m6_b1;  // [bp-0x6]" not in pruned
    assert "char s_fffa;" in pruned


def test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores(monkeypatch):
    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "1")
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadProgram")

    assert result.returncode == 0, result.stderr
    assert "validation=passed" in result.stderr
    assert result.stdout.count("err = loadprog(") == 1
    _assert_has_all(
        result.stdout,
        (
            "if (err)\n        return err;",
            "cs[0] = exeLoadParams[10];",
            "ss[0] = exeLoadParams[8];",
            "return 0;",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "MK_FP(ds,",
            "SEG_U8(inertia_ss,",
            "cs[1]",
            "ss[1]",
            "ax = exeLoadParams",
        ),
    )
    compile_result = check_c_recompiles_8616(result.stdout, target="portable-flat")
    assert compile_result.passed, compile_result.stderr


def test_prune_dead_local_assignments_removes_unused_constant_stores():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    dead_var = SimStackVariable(4, 2, base="bp", name="dead", region=0x1000)
    live_var = SimStackVariable(6, 2, base="bp", name="live", region=0x1000)
    dead_cvar = structured_c.CVariable(dead_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                dead_cvar, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen
            ),
            structured_c.CAssignment(
                live_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    live_cvar,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        variables_in_use={
            dead_var: dead_cvar,
            live_var: live_cvar,
        },
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert codegen.cfunc.statements.statements[0].lhs.variable is live_var


def test_prune_dead_local_assignments_removes_overwritten_local_stores():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    local_var = SimStackVariable(-2, 2, base="bp", name="local", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    overwritten = structured_c.CStatements(
        [
            structured_c.CAssignment(
                local_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                local_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CReturn(local_cvar, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=overwritten,
        variables_in_use={local_var: local_cvar},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].rhs.value == 2
    assert codegen.cfunc.statements.statements[1].retval.variable is local_var


def test_prune_dead_local_assignments_removes_overwritten_storage_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    first_var = SimStackVariable(-2, 2, base="bp", name="first", region=0x1000)
    second_var = SimStackVariable(-2, 2, base="bp", name="second", region=0x1000)
    first_cvar = structured_c.CVariable(first_var, variable_type=SimTypeShort(False), codegen=codegen)
    second_cvar = structured_c.CVariable(second_var, variable_type=SimTypeShort(False), codegen=codegen)
    overwritten = structured_c.CStatements(
        [
            structured_c.CAssignment(
                first_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                second_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CReturn(second_cvar, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=overwritten,
        variables_in_use={
            first_var: first_cvar,
            second_var: second_cvar,
        },
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert codegen.cfunc.statements.statements[0].rhs.value == 2
    assert codegen.cfunc.statements.statements[1].retval.variable is second_var


def test_prune_dead_local_assignments_removes_redundant_call_before_same_return():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    call = structured_c.CFunctionCall(
        "loadprog",
        SimpleNamespace(name="loadprog"),
        [
            structured_c.CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                structured_c.CVariable(SimStackVariable(-4, 2, base="bp", region=0x1000), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [
            call,
            structured_c.CReturn(
                structured_c.CFunctionCall(
                    "loadprog",
                    SimpleNamespace(name="loadprog"),
                    [
                        structured_c.CVariable(SimStackVariable(-4, 2, base="bp", region=0x1000), codegen=codegen),
                        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        variables_in_use={},
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)


def test_prune_dead_local_assignments_matches_normalized_call_signature():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    shared_var = SimStackVariable(-4, 2, base="bp", name="arg", region=0x1000)
    call = structured_c.CFunctionCall(
        "loadprog",
        SimpleNamespace(name="loadprog"),
        [
            structured_c.CTypeCast(
                SimTypeShort(False),
                SimTypeShort(False),
                structured_c.CVariable(shared_var, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [
            call,
            structured_c.CReturn(
                structured_c.CFunctionCall(
                    "loadprog",
                    SimpleNamespace(name="loadprog"),
                    [
                        structured_c.CVariable(shared_var, codegen=codegen),
                        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=statements, variables_in_use={})

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CReturn)


def test_resolve_stack_cvar_at_offset_prefers_canonical_argument_storage():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.cfunc = SimpleNamespace(arg_list=[], variables_in_use={})

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    alias_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.variables_in_use = {
        arg_var: arg_cvar,
        alias_var: alias_cvar,
    }

    resolved = decompile._resolve_stack_cvar_at_offset(codegen, 4)
    canonical = decompile._canonicalize_stack_cvar_expr(alias_cvar, codegen)

    assert resolved is arg_cvar
    assert canonical is arg_cvar


def test_collapse_annotated_stack_aliases_text_prefers_argument_name():
    c_text = (
        "unsigned short _strlen(unsigned short s)\n"
        "{\n"
        "    unsigned short n;  // [bp-0x2] n\n"
        "    unsigned short s_3; // [bp+0x4] s\n"
        "\n"
        "    n = 0;\n"
        "    while (*s_3++)\n"
        "        n += 1;\n"
        "    return (n);\n"
        "}\n"
    )

    collapsed = decompile._collapse_annotated_stack_aliases_text(c_text)

    assert "unsigned short s_3;" in collapsed
    assert "while (*s_3++)" in collapsed
    assert "n += 1;" in collapsed
    assert "while (*s++)" not in collapsed


def test_simplify_x86_16_stack_byte_pointers_rewrites_segment_math():
    c_text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((unsigned short far *)MK_FP(ds, (unsigned int)cs_2)) = ir_3_2;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_bda_linear_constants():
    c_text = "    *((unsigned short *)1047) = es;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((unsigned short far *)MK_FP(0x40, 0x17)) = es;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_byte_walk_loop():
    c_text = (
        "    while (true)\n"
        "    {\n"
        "        ir_3 = s;\n"
        "        ir_4 = s;\n"
        "        s = (ir_3 | ir_4 * 0x100) + 1 >> 8;\n"
        "        if (!(s + 1))\n"
        "            break;\n"
        "        ir_8 = n;\n"
        "        ir_9 = n;\n"
        "        n = (ir_8 | ir_9 * 0x100) + 1 >> 8;\n"
        "    }\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    while (*s++)\n    {\n        n += 1;\n    }\n\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_ss_stack_alias_chains():
    c_text = (
        "    vvar_20 = (int)&(&s_a)[2];\n"
        "    *((unsigned short *)((ss << 4) + vvar_20 - 2)) = 0;\n"
        "    vvar_24 = vvar_20 - 2 + -2;\n"
        "    *((char *)((ss << 4) + vvar_24)) = cs;\n"
        "    *((char *)(vvar_24 + 1)) = cs >> 8;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    vvar_20 = (int)&(&s_a)[2];\n"
        "    *((unsigned short *)&s_a) = 0;\n"
        "    vvar_24 = vvar_20 - 2 + -2;\n"
        "    *((char *)(&s_a - 2)) = cs;\n"
        "    *((char *)(&s_a - 1)) = cs >> 8;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_segmented_byte_pair_loads():
    c_text = (
        "    x = (*((char *)((ds << 4) + 2978)) | *((char *)((ds << 4) + 2978 + 1)) << 8) - 1;\n"
        "    y = (*((char *)((ss << 4) + (unsigned int)&s_4)) | *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) << 8) + 1;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    x = *((unsigned short far *)MK_FP(ds, 2978)) - 1;\n    y = *((unsigned short *)&s_4) + 1;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_direct_ss_local_stores():
    c_text = (
        "    *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8;\n"
        "    *((unsigned short *)((ss << 4) + (unsigned int)&s_4 - 2)) = 0;\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((char *)(&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8;\n    *((unsigned short *)(&s_4 - 2)) = 0;\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_direct_ss_local_exprs_inside_for_header():
    c_text = (
        "    for (; ; *((char *)((ss << 4) + (unsigned int)&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8)\n"
        "    {\n"
        "    }\n"
    )

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    for (; ; *((char *)(&s_4 + 1)) = *((unsigned short *)&s_4) + 1 >> 8)\n    {\n    }\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_indexed_ss_local_store_shape():
    c_text = "    (&s_8)[16 * ss] = cs;\n    (&s_7)[16 * ss] = cs >> 8;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(c_text) == (
        "    *((char *)&s_8) = cs;\n    *((char *)&s_7) = cs >> 8;\n"
    )


def test_decompiler_return_compat_falls_back_when_return_expression_is_unsupported():
    original_handle_return = ReturnMaker._handle_Return
    calls: list[tuple[int, object, object]] = []

    def fake_handle_return(self, stmt_idx, stmt, block):
        calls.append((stmt_idx, stmt, block))
        return "orig"

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        fake_stmt = SimpleNamespace(ret_exprs=[], copy=lambda: SimpleNamespace(ret_exprs=[]), tags={"ins_addr": 0x1000})
        fake_block = SimpleNamespace(statements=[fake_stmt], copy=lambda **kwargs: SimpleNamespace(**kwargs))
        fake_cc = SimpleNamespace(return_val=lambda _returnty: object())
        fake_function = SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimpleNamespace()), calling_convention=fake_cc
        )
        fake_self = SimpleNamespace(
            function=fake_function, arch=SimpleNamespace(byte_width=2), _next_atom=lambda: 1, _new_block=None
        )

        result = ReturnMaker._handle_Return(fake_self, 0, fake_stmt, fake_block)

        assert result == "orig"
        assert calls
        assert fake_self._new_block is None
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_refuses_stack_base_return_register():
    original_handle_return = ReturnMaker._handle_Return
    calls = []

    def fake_handle_return(self, stmt_idx, stmt, block):
        calls.append((stmt_idx, stmt, block))
        return "fallback"

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        fake_stmt = SimpleNamespace(ret_exprs=[], copy=lambda: SimpleNamespace(ret_exprs=[]), tags={"ins_addr": 0x2000})
        fake_function = SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("sp", 2)),
        )
        fake_self = SimpleNamespace(
            function=fake_function,
            arch=SimpleNamespace(registers={"sp": (4, 2), "translate_register_name": lambda reg_name, size: reg_name}),
            _next_atom=lambda: 1,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, fake_stmt, None)

        assert result == "fallback"
        assert calls, "expected fallback path"
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_uses_ax_for_x86_16_near_pointer_return():
    original_handle_return = ReturnMaker._handle_Return
    fallback_calls = []
    cc_calls = []

    def fake_handle_return(self, stmt_idx, stmt, block):
        fallback_calls.append((self, stmt_idx, stmt, block))
        return "fallback"

    def generic_pointer_return(_returnty):
        cc_calls.append(_returnty)
        return SimRegArg("dx", 4)

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        ret_stmt = SimpleNamespace(
            ret_exprs=[],
            copy=lambda: SimpleNamespace(ret_exprs=[]),
            tags={"ins_addr": 0x2000},
        )
        block = SimpleNamespace(statements=[ret_stmt])
        fake_function = SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimTypePointer(SimTypeChar(False))),
            calling_convention=SimpleNamespace(return_val=generic_pointer_return),
            addr=0x2000,
        )
        fake_arch = SimpleNamespace(
            name="86_16",
            byte_width=8,
            registers={"ax": (0, 2)},
            translate_register_name=lambda _offset, _size: "ax",
        )
        fake_self = SimpleNamespace(
            function=fake_function,
            arch=fake_arch,
            _next_atom=lambda: 1,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, ret_stmt, block)

        assert fallback_calls == []
        assert cc_calls == []
        assert len(result.ret_exprs) == 1
        ret_expr = result.ret_exprs[0]
        assert isinstance(ret_expr, ailment.Expr.Register)
        assert ret_expr.reg_offset == 0
        assert ret_expr.bits == 16
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_refuses_cross_block_terminal_ax_substitution():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, nodes, predecessors):
            self._nodes = tuple(nodes)
            self._predecessors = predecessors

        def nodes(self):
            return self._nodes

        def predecessors(self, node):
            return tuple(self._predecessors.get(id(node), ()))

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        ax_a = ailment.Expr.Register(1, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x1010)
        ax_b = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x1012)
        assign_a = ailment.Stmt.Assignment(
            3,
            ax_a,
            ailment.Expr.Const(4, 0x1111, 16, ins_addr=0x1010),
            ins_addr=0x1010,
        )
        assign_b = ailment.Stmt.Assignment(
            5,
            ax_b,
            ailment.Expr.Const(6, 0x2222, 16, ins_addr=0x1012),
            ins_addr=0x1012,
        )
        block_a = SimpleNamespace(statements=[assign_a])
        block_b = SimpleNamespace(statements=[assign_b])
        ret_stmt = SimpleNamespace(
            ret_exprs=[],
            copy=lambda: SimpleNamespace(ret_exprs=[]),
            tags={"ins_addr": 0x1020},
        )
        ret_block = SimpleNamespace(statements=[ret_stmt])
        graph = _FakeGraph((block_a, block_b, ret_block), {id(ret_block): (block_a, block_b)})
        fake_function = SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
            addr=0x2000,
        )
        fake_self = SimpleNamespace(
            function=fake_function,
            arch=arch,
            graph=graph,
            _next_atom=lambda: 1,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, ret_stmt, ret_block)

        assert len(result.ret_exprs) == 1
        ret_expr = result.ret_exprs[0]
        assert isinstance(ret_expr, ailment.Expr.Register)
        assert ret_expr.reg_offset == arch.registers["ax"][0]
        assert ret_expr.bits == 16
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_infers_ax_stack_load_without_prototype():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

        def predecessors(self, _node):
            return []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        bp = ailment.Expr.Register(1, arch.registers["bp"][0], 16, reg_name="bp", ins_addr=0x100B4)
        two = ailment.Expr.Const(2, 2, 16, ins_addr=0x100B4)
        bp_minus_two = ailment.Expr.BinaryOp(3, "Sub", [bp, two], bits=16, ins_addr=0x100B4)
        stack_load = ailment.Expr.Load(4, bp_minus_two, 2, arch.memory_endness, ins_addr=0x100B4)
        ax = ailment.Expr.Register(5, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B4)
        assignment = ailment.Stmt.Assignment(6, ax, stack_load, ins_addr=0x100B4)
        ret_stmt = ailment.Stmt.Return(7, [], ins_addr=0x100BF)
        block = SimpleNamespace(statements=[assignment, ret_stmt])
        function = SimpleNamespace(addr=0x1000, prototype=None, calling_convention=None)
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 1, ret_stmt, block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        retval = result.ret_exprs[0]
        assert isinstance(retval, ailment.Expr.Register)
        assert (retval.reg_offset, retval.bits, retval.tags["ins_addr"]) == (ax.reg_offset, ax.bits, ret_stmt.tags["ins_addr"])
        assert function._inertia_return_compat_ax_materialized_count == 1
        # Source evidence proves existence; only SSA may propagate it to RET.
        retval = cast(Load, _infer_x86_16_ax_return_expr_8616(fake_self, ret_stmt, block))
        assert isinstance(retval, Load)
        assert isinstance(retval.addr, StackBaseOffset)
        assert isinstance(retval.addr.tags.get("variable"), SimStackVariable)
        assert retval.addr.tags["variable"].base == "bp"
        assert retval.addr.offset == -2
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_resolves_ax_self_update_return_source():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

        def predecessors(self, _node):
            return []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        bp = ailment.Expr.Register(1, arch.registers["bp"][0], 16, reg_name="bp", ins_addr=0x100B4)
        four = ailment.Expr.Const(2, 4, 16, ins_addr=0x100B4)
        bp_plus_four = ailment.Expr.BinaryOp(3, "Add", [bp, four], bits=16, ins_addr=0x100B4)
        stack_load = ailment.Expr.Load(4, bp_plus_four, 2, arch.memory_endness, ins_addr=0x100B4)
        ax_dst = ailment.Expr.Register(5, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B4)
        load_assignment = ailment.Stmt.Assignment(6, ax_dst, stack_load, ins_addr=0x100B4)
        ax_read = ailment.Expr.Register(7, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B5)
        one = ailment.Expr.Const(8, 1, 16, ins_addr=0x100B5)
        inc_expr = ailment.Expr.BinaryOp(9, "Add", [ax_read, one], bits=16, ins_addr=0x100B5)
        ax_dst_update = ailment.Expr.Register(10, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B5)
        inc_assignment = ailment.Stmt.Assignment(11, ax_dst_update, inc_expr, ins_addr=0x100B5)
        ret_stmt = ailment.Stmt.Return(12, [], ins_addr=0x100BF)
        block = SimpleNamespace(statements=[load_assignment, inc_assignment, ret_stmt])
        function = SimpleNamespace(addr=0x1000, prototype=None, calling_convention=None)
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 2, ret_stmt, block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        retval = result.ret_exprs[0]
        assert isinstance(retval, ailment.Expr.Register)
        assert (retval.reg_offset, retval.bits, retval.tags["ins_addr"]) == (ax_dst.reg_offset, ax_dst.bits, ret_stmt.tags["ins_addr"])
        retval = cast(BinaryOp, _infer_x86_16_ax_return_expr_8616(fake_self, ret_stmt, block))
        assert isinstance(retval, BinaryOp)
        assert retval.op == "Add"
        load_expr, const_expr = retval.operands
        assert isinstance(load_expr, ailment.Expr.Load)
        assert isinstance(load_expr.addr, StackBaseOffset)
        assert isinstance(load_expr.addr.tags.get("variable"), SimStackVariable)
        assert load_expr.addr.tags["variable"].base == "bp"
        assert load_expr.addr.offset == 4
        assert isinstance(const_expr, ailment.Expr.Const)
        assert const_expr.value == 1
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_refuses_ax_inference_for_source_proven_void():
    original_handle_return = ReturnMaker._handle_Return
    calls: list[tuple[int, object, object]] = []

    def fake_handle_return(_self, stmt_idx, stmt, block):
        calls.append((stmt_idx, stmt, block))
        return "fallback"

    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

        def predecessors(self, _node):
            return []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        value = ailment.Expr.Const(1, 75, 16, ins_addr=0x10517)
        ax = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10517)
        assignment = ailment.Stmt.Assignment(3, ax, value, ins_addr=0x10517)
        ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
        block = SimpleNamespace(statements=[assignment, ret_stmt])
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeBottom(label="void")),
            calling_convention=None,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 1, ret_stmt, block)

        assert result == "fallback"
        assert calls == [(1, ret_stmt, block)]
        assert getattr(function, "_inertia_return_compat_ax_materialized_count", 0) == 0
        assert getattr(function, "_inertia_return_compat_void_refused_count", 0) == 1
    finally:
        ReturnMaker._handle_Return = original_handle_return


@pytest.mark.parametrize(
    ("intervening_conditional", "expected_return_count"),
    ((False, 1), (True, 0)),
    ids=("terminal-scalar", "branched-stale-scalar"),
)
def test_decompiler_return_compat_requires_unbranched_scalar_for_unused_caller(
    intervening_conditional: bool,
    expected_return_count: int,
):
    original_handle_return = ReturnMaker._handle_Return
    fallback_calls: list[tuple[int, object, object]] = []

    def fake_handle_return(_self, stmt_idx, stmt, block):
        fallback_calls.append((stmt_idx, stmt, block))
        return "fallback"

    class _FakeGraph:
        def __init__(self, nodes):
            self._nodes = tuple(nodes)

        def nodes(self):
            return self._nodes

        def predecessors(self, _node):
            return ()

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        value = ailment.Expr.Const(1, 75, 16, ins_addr=0x10517)
        ax = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10517)
        assignment = ailment.Stmt.Assignment(3, ax, value, ins_addr=0x10517)
        condition = ailment.Expr.Const(4, 1, 1, ins_addr=0x10519)
        true_target = ailment.Expr.Const(5, 0x1051F, 16, ins_addr=0x10519)
        false_target = ailment.Expr.Const(6, 0x1051D, 16, ins_addr=0x10519)
        conditional = ailment.Stmt.ConditionalJump(
            7,
            condition,
            true_target,
            false_target,
            ins_addr=0x10519,
        )
        ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
        pred_block = SimpleNamespace(statements=[assignment])
        ret_block = SimpleNamespace(
            statements=[assignment, *([conditional] if intervening_conditional else []), ret_stmt]
        )
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
            is_prototype_guessed=True,
            _inertia_return_compat_caller_uses_return_8616=False,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph((pred_block, ret_block)),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, len(ret_block.statements) - 1, ret_stmt, ret_block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == expected_return_count
        if expected_return_count:
            captured = result.ret_exprs[0]
            assert isinstance(captured, ailment.Expr.Register)
            assert (captured.reg_offset, captured.bits, captured.tags["ins_addr"]) == (ax.reg_offset, ax.bits, ret_stmt.tags["ins_addr"])
            assert isinstance(assignment.src, ailment.Expr.Const)
            assert (assignment.src.value, assignment.src.bits) == (value.value, value.bits)
        assert fallback_calls == []
        assert isinstance(function.prototype.returnty, SimTypeShort)
        assert function.is_prototype_guessed is True
        assert getattr(function, "_inertia_return_compat_guessed_scalar_void_promoted_count", 0) == 0
        assert (
            getattr(function, "_inertia_return_compat_unused_caller_proven_return_materialized_count", 0)
            == expected_return_count
        )
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_classifies_only_unusable_c_results_for_neutralization():
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    return_type = SimTypeShort(False).with_arch(arch)
    unresolved = structured_c.CVariable(
        SimRegisterVariable(arch.registers["ax"][0], 2, name="vvar_32"),
        variable_type=return_type,
        codegen=codegen,
    )
    valid = structured_c.CConstant(7, return_type, codegen=codegen)
    dirty_register = ailment.Expr.VirtualVariable(
        2,
        32,
        16,
        ailment.expression.VirtualVariableCategory.REGISTER,
        oident=arch.registers["ax"][0],
    )
    unresolved_dirty = structured_c.CTypeCast(
        return_type,
        return_type,
        structured_c.CDirtyExpression(dirty_register, codegen=codegen),
        codegen=codegen,
    )
    non_scalar = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch),
        codegen=codegen,
    )

    assert _return_compat_c_result_needs_neutralization_8616(None, return_type) is True
    assert _return_compat_c_result_needs_neutralization_8616(unresolved, return_type) is True
    assert _return_compat_c_result_needs_neutralization_8616(unresolved_dirty, return_type) is True
    assert _return_compat_c_result_needs_neutralization_8616(
        structured_c.CBinaryOp(
            "Add", valid, structured_c.CFakeVariable("stack_base", return_type, codegen=codegen), codegen=codegen
        ),
        return_type,
    ) is True
    assert _return_compat_c_result_needs_neutralization_8616(non_scalar, return_type) is True
    assert _return_compat_c_result_needs_neutralization_8616(valid, return_type) is False


def test_decompiler_return_compat_uses_original_addr_for_exact_region_callers(monkeypatch):
    import angr_platforms.X86_16.analysis_helpers as analysis_helpers
    import angr_platforms.X86_16.callsite_summary as callsite_summary

    caller = SimpleNamespace(name="caller")
    target = SimpleNamespace(target_addr=0x10CE0, callsite_addr=0x1042)
    functions = SimpleNamespace(values=lambda: (caller,))
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=functions),
        _inertia_original_linear_delta=0xFCE0,
    )
    function = SimpleNamespace(addr=0x1000, project=project)

    monkeypatch.setattr(analysis_helpers, "collect_neighbor_call_targets", lambda candidate: (target,))
    monkeypatch.setattr(
        callsite_summary,
        "summarize_x86_16_callsite",
        lambda candidate, callsite_addr: SimpleNamespace(return_used=False),
    )

    assert _return_compat_function_caller_return_use_8616(function) is False


def test_decompiler_return_compat_uses_original_project_for_exact_region_callers(monkeypatch):
    import angr_platforms.X86_16.analysis_helpers as analysis_helpers
    import angr_platforms.X86_16.callsite_summary as callsite_summary

    caller = SimpleNamespace(name="caller")
    target = SimpleNamespace(target_addr=0x10CE0, callsite_addr=0x1042)
    original_functions = SimpleNamespace(values=lambda: (caller,))
    original_project = SimpleNamespace(kb=SimpleNamespace(functions=original_functions))
    sliced_project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(values=lambda: ())),
        _inertia_original_linear_delta=0xFCE0,
        _inertia_original_project=original_project,
    )
    function = SimpleNamespace(addr=0x1000, project=sliced_project)

    monkeypatch.setattr(analysis_helpers, "collect_neighbor_call_targets", lambda candidate: (target,))
    monkeypatch.setattr(
        callsite_summary,
        "summarize_x86_16_callsite",
        lambda candidate, callsite_addr: SimpleNamespace(return_used=False),
    )

    assert _return_compat_function_caller_return_use_8616(function) is False


def test_decompiler_return_compat_uses_private_project_for_exact_region_callers(monkeypatch):
    import angr_platforms.X86_16.analysis_helpers as analysis_helpers
    import angr_platforms.X86_16.callsite_summary as callsite_summary

    caller = SimpleNamespace(name="caller")
    target = SimpleNamespace(target_addr=0x10CE0, callsite_addr=0x1042)
    original_functions = SimpleNamespace(values=lambda: (caller,))
    original_project = SimpleNamespace(kb=SimpleNamespace(functions=original_functions))
    sliced_project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(values=lambda: ())),
        _inertia_original_linear_delta=0xFCE0,
        _inertia_original_project=original_project,
    )
    function = SimpleNamespace(addr=0x1000, _project=sliced_project)

    monkeypatch.setattr(analysis_helpers, "collect_neighbor_call_targets", lambda candidate: (target,))
    monkeypatch.setattr(
        callsite_summary,
        "summarize_x86_16_callsite",
        lambda candidate, callsite_addr: SimpleNamespace(return_used=False),
    )

    assert _return_compat_function_caller_return_use_8616(function) is False


def test_decompiler_return_compat_does_not_count_function_return_as_direct_use(monkeypatch):
    import angr_platforms.X86_16.analysis_helpers as analysis_helpers
    import angr_platforms.X86_16.callsite_summary as callsite_summary

    caller = SimpleNamespace(name="caller")
    target = SimpleNamespace(target_addr=0x1200, callsite_addr=0x1042)
    functions = SimpleNamespace(values=lambda: (caller,))
    project = SimpleNamespace(kb=SimpleNamespace(functions=functions))
    function = SimpleNamespace(addr=0x1200, project=project)

    monkeypatch.setattr(analysis_helpers, "collect_neighbor_call_targets", lambda candidate: (target,))
    monkeypatch.setattr(
        callsite_summary,
        "summarize_x86_16_callsite",
        lambda candidate, callsite_addr: SimpleNamespace(
            return_used=True,
            return_use_kind=CallsiteReturnUseKind8616.FUNCTION_RETURN,
        ),
    )

    assert _return_compat_function_caller_return_use_8616(function) is False


def test_decompiler_return_compat_keeps_guessed_scalar_when_caller_uses_return():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

        def predecessors(self, _node):
            return []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        value = ailment.Expr.Const(1, 75, 16, ins_addr=0x10517)
        ax = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10517)
        assignment = ailment.Stmt.Assignment(3, ax, value, ins_addr=0x10517)
        ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
        ret_block = SimpleNamespace(statements=[assignment, ret_stmt])
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
            is_prototype_guessed=True,
            _inertia_return_compat_caller_uses_return_8616=True,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(ret_block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 1, ret_stmt, ret_block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        captured = result.ret_exprs[0]
        assert isinstance(captured, ailment.Expr.Register)
        assert (captured.reg_offset, captured.bits, captured.tags["ins_addr"]) == (ax.reg_offset, ax.bits, ret_stmt.tags["ins_addr"])
        assert isinstance(assignment.src, ailment.Expr.Const)
        assert (assignment.src.value, assignment.src.bits) == (value.value, value.bits)
        assert isinstance(function.prototype.returnty, SimTypeShort)
        assert getattr(function, "_inertia_return_compat_guessed_scalar_refused_count", 0) == 0
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_keeps_unknown_caller_unconditional_predecessor_return():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, pred_block, ret_block):
            self._pred_block = pred_block
            self._ret_block = ret_block

        def nodes(self):
            return [self._pred_block, self._ret_block]

        def predecessors(self, node):
            return [self._pred_block] if node is self._ret_block else []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        value = ailment.Expr.Const(1, 75, 16, ins_addr=0x10517)
        ax = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10517)
        assignment = ailment.Stmt.Assignment(3, ax, value, ins_addr=0x10517)
        jump = ailment.Stmt.Jump(4, ailment.Expr.Const(5, 0x10530, 16, ins_addr=0x1051A), ins_addr=0x1051A)
        ret_stmt = ailment.Stmt.Return(6, [], ins_addr=0x10530)
        pred_block = SimpleNamespace(statements=[assignment, jump])
        ret_block = SimpleNamespace(statements=[ret_stmt])
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=None,
            is_prototype_guessed=True,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(pred_block, ret_block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, ret_stmt, ret_block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        captured = result.ret_exprs[0]
        assert isinstance(captured, ailment.Expr.Register)
        assert (captured.reg_offset, captured.bits, captured.tags["ins_addr"]) == (ax.reg_offset, ax.bits, ret_stmt.tags["ins_addr"])
        assert pred_block.statements == [assignment, jump]
        assert isinstance(assignment.src, ailment.Expr.Const)
        assert (assignment.src.value, assignment.src.bits) == (value.value, value.bits)
        assert isinstance(function.prototype.returnty, SimTypeShort)
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_keeps_unknown_caller_reaching_ax_register_return():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, pred_a, pred_b, ret_block):
            self._pred_a = pred_a
            self._pred_b = pred_b
            self._ret_block = ret_block

        def nodes(self):
            return [self._pred_a, self._pred_b, self._ret_block]

        def predecessors(self, node):
            return [self._pred_a, self._pred_b] if node is self._ret_block else []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        ax_a = ailment.Expr.Register(1, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10510)
        ax_b = ailment.Expr.Register(2, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x10520)
        assign_a = ailment.Stmt.Assignment(
            3,
            ax_a,
            ailment.Expr.Const(4, 0, 16, ins_addr=0x10510),
            ins_addr=0x10510,
        )
        assign_b = ailment.Stmt.Assignment(
            5,
            ax_b,
            ailment.Expr.Const(6, 75, 16, ins_addr=0x10520),
            ins_addr=0x10520,
        )
        jump_a = ailment.Stmt.Jump(7, ailment.Expr.Const(8, 0x10530, 16, ins_addr=0x10512), ins_addr=0x10512)
        jump_b = ailment.Stmt.Jump(9, ailment.Expr.Const(10, 0x10530, 16, ins_addr=0x10522), ins_addr=0x10522)
        ret_stmt = ailment.Stmt.Return(11, [], ins_addr=0x10530)
        pred_a = SimpleNamespace(statements=[assign_a, jump_a])
        pred_b = SimpleNamespace(statements=[assign_b, jump_b])
        ret_block = SimpleNamespace(statements=[ret_stmt])
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
            is_prototype_guessed=True,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(pred_a, pred_b, ret_block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, ret_stmt, ret_block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        assert isinstance(result.ret_exprs[0], ailment.Expr.Register)
        assert result.ret_exprs[0].reg_offset == arch.registers["ax"][0]
        assert result.ret_exprs[0].bits == 16
        assert getattr(function, "_inertia_return_compat_unknown_caller_reaching_ax_count", 0) == 1
        assert getattr(function, "_inertia_return_compat_guessed_scalar_void_promoted_count", 0) == 0
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_keeps_unresolved_c_return_carrier_for_unknown_caller():
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimRegisterVariable(0, 2, name="vvar_21")
    unresolved_retval = structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=codegen)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        is_prototype_guessed=True,
    )

    assert _return_compat_should_drop_unresolved_c_return_8616(function, unresolved_retval) is False


def test_decompiler_return_compat_keeps_unresolved_c_return_for_unused_caller():
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimRegisterVariable(0, 2, name="vvar_21")
    unresolved_retval = structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=codegen)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        is_prototype_guessed=True,
        _inertia_return_compat_caller_uses_return_8616=False,
    )

    assert _return_compat_should_drop_unresolved_c_return_8616(function, unresolved_retval) is False


def test_decompiler_return_compat_keeps_unresolved_c_return_when_reaching_ax_is_proven():
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimRegisterVariable(0, 2, name="vvar_21")
    unresolved_retval = structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=codegen)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        is_prototype_guessed=True,
        _inertia_return_compat_unknown_caller_reaching_ax_count=1,
    )

    assert _return_compat_should_drop_unresolved_c_return_8616(function, unresolved_retval) is False


def test_decompiler_return_compat_keeps_unknown_caller_scalar_prototype_as_ax_carrier():
    original_handle_return = ReturnMaker._handle_Return

    def fake_handle_return(_self, _stmt_idx, _stmt, _block):
        return "fallback"

    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

        def predecessors(self, _node):
            return []

    try:
        ReturnMaker._handle_Return = fake_handle_return
        apply_x86_16_decompiler_return_compatibility()

        arch = Arch86_16()
        ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
        ret_block = SimpleNamespace(statements=[ret_stmt])
        function = SimpleNamespace(
            addr=0x1000,
            prototype=SimpleNamespace(returnty=SimTypeShort(False)),
            calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
            is_prototype_guessed=True,
        )
        fake_self = SimpleNamespace(
            function=function,
            graph=_FakeGraph(ret_block),
            arch=arch,
            _next_atom=lambda: 99,
            _new_block=None,
        )

        result = ReturnMaker._handle_Return(fake_self, 0, ret_stmt, ret_block)

        assert isinstance(result, ailment.Stmt.Return)
        assert len(result.ret_exprs) == 1
        assert isinstance(result.ret_exprs[0], ailment.Expr.Register)
        assert result.ret_exprs[0].reg_offset == arch.registers["ax"][0]
        assert result.ret_exprs[0].bits == 16
        assert isinstance(function.prototype.returnty, SimTypeShort)
        assert function.is_prototype_guessed is True
        assert getattr(function, "_inertia_return_compat_unknown_caller_no_terminal_ax_count", 0) == 1
        assert getattr(function, "_inertia_return_compat_guessed_scalar_refused_count", 0) == 0
        assert getattr(function, "_inertia_return_compat_guessed_scalar_void_promoted_count", 0) == 0
    finally:
        ReturnMaker._handle_Return = original_handle_return


def test_decompiler_return_compat_resolves_codegen_prototype_from_kb():
    prototype = SimpleNamespace(returnty=SimTypeBottom(label="void"))
    kb_func = SimpleNamespace(prototype=prototype)

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return kb_func if addr == 0x1000 else None

    cfunc = SimpleNamespace(addr=0x1000, functy=SimpleNamespace(returnty=None), prototype=None)
    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))
    codegen_func = SimpleNamespace(prototype=SimpleNamespace(returnty=None), project=project)
    codegen = SimpleNamespace(
        _func=codegen_func,
        cfunc=cfunc,
        project=None,
    )

    resolved_func, resolved_prototype = _resolve_codegen_prototype_8616(codegen)

    assert resolved_func is codegen_func
    assert resolved_prototype is prototype
    assert codegen_func.prototype is prototype
    assert cfunc.prototype is prototype
    assert cfunc.functy is prototype
    assert kb_func._inertia_return_compat_codegen_prototype_resolved_count == 1


def test_decompiler_return_compat_detects_void_from_cfunc_prototype():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    prototype = SimpleNamespace(returnty=SimTypeBottom(label="void"))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=prototype, prototype=None), _func=None)

    assert codegen_has_explicit_void_return_8616(project, codegen) is True


def test_decompiler_return_compat_detects_void_from_kb_function():
    prototype = SimpleNamespace(returnty=SimTypeBottom(label="void"))
    kb_func = SimpleNamespace(prototype=prototype)

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return kb_func if addr == 0x1000 else None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))
    cfunc = SimpleNamespace(addr=0x1000, functy=SimpleNamespace(returnty=None), prototype=None)
    codegen = SimpleNamespace(cfunc=cfunc, _func=SimpleNamespace(prototype=None, project=project))

    assert codegen_has_explicit_void_return_8616(project, codegen) is True
    assert cfunc.prototype is prototype


def test_decompiler_return_compat_detects_nonreturning_function_as_void():
    function = SimpleNamespace(prototype=None, returning=False)
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000), _func=None, _inertia_current_function_8616=function)

    assert codegen_has_explicit_void_return_8616(project, codegen) is True


def test_decompiler_return_compat_refuses_nonvoid_prototype():
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    prototype = SimpleNamespace(returnty=SimTypeShort(False))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=prototype, prototype=None), _func=None)

    assert codegen_has_explicit_void_return_8616(project, codegen) is False


def test_missing_terminal_ax_return_refuses_source_proven_void_over_incomplete_codegen_proto():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=c_codegen),
        functy=SimpleNamespace(returnty=None),
        prototype=None,
    )
    function = SimpleNamespace(prototype=SimpleNamespace(returnty=SimTypeBottom(label="void")))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_current_function_8616=function)

    changed = _materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is False
    assert getattr(codegen, "_inertia_missing_terminal_ax_return_refused_void_8616", 0) == 1
    assert cfunc.statements.statements == []


def test_ast_void_return_prune_preserves_call_side_effects_and_drops_values():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    call = structured_c.CFunctionCall("Sleep", None, [], codegen=c_codegen)
    root = structured_c.CStatements(
        [
            structured_c.CReturn(call, codegen=c_codegen),
            structured_c.CReturn(
                structured_c.CConstant(75, SimTypeShort(False), codegen=c_codegen),
                codegen=c_codegen,
            ),
        ],
        codegen=c_codegen,
    )
    codegen = SimpleNamespace(
        _func=SimpleNamespace(prototype=SimpleNamespace(returnty=SimTypeBottom(label="void"))),
        cfunc=SimpleNamespace(
            functy=SimpleNamespace(returnty=None),
            prototype=None,
            statements=root,
        ),
    )

    changed = _cli_c_ast_rewrites._prune_void_function_return_values(codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[0], structured_c.CExpressionStatement)
    assert statements[0].expr is call
    assert isinstance(statements[1], structured_c.CReturn)
    assert statements[1].retval is None


def test_void_empty_return_guard_prune_requires_surplus_over_real_jcc_budget(monkeypatch):
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    real_cond = structured_c.CVariable(
        SimRegisterVariable(0x10, 2, name="real_cond"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond = structured_c.CBinaryOp(
        "Shr",
        structured_c.CVariable(
            SimRegisterVariable(0x12, 2, name="mul_tmp"),
            variable_type=SimTypeShort(False),
            codegen=c_codegen,
        ),
        structured_c.CConstant(15, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    artifact_cond.tags = {"ins_addr": 0x2000, "vex_block_addr": 0x1FF0}
    real_if = structured_c.CIfElse(
        [
            (
                real_cond,
                structured_c.CStatements(
                    [
                        structured_c.CFunctionCall("Sleep", None, [], codegen=c_codegen),
                        structured_c.CReturn(None, codegen=c_codegen),
                    ],
                    codegen=c_codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    artifact_if = structured_c.CIfElse(
        [
            (
                artifact_cond,
                structured_c.CStatements(
                    [structured_c.CReturn(None, codegen=c_codegen)],
                    codegen=c_codegen,
                ),
            )
        ],
        else_node=structured_c.CStatements([], codegen=c_codegen),
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    tail_call = structured_c.CFunctionCall("Beep", None, [], codegen=c_codegen)
    root = structured_c.CStatements([real_if, artifact_if, tail_call], codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            prototype=None,
            statements=root,
        ),
        _inertia_current_function_8616=SimpleNamespace(prototype=SimpleNamespace(returnty=SimTypeBottom(label="void"))),
    )
    monkeypatch.setattr(_postprocess_stage, "_real_conditional_branch_count_for_codegen_8616", lambda *_args: 1)
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda *_args, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="imul"),))
            )
        )
    )

    changed = _postprocess_stage._prune_surplus_void_empty_return_guards_8616(project, codegen)

    assert changed is True
    assert root.statements == [real_if, tail_call]
    assert getattr(codegen, "_inertia_void_empty_return_guard_candidates_8616", 0) == 1
    assert getattr(codegen, "_inertia_void_empty_return_guard_pruned_8616", 0) == 1
    assert (
        getattr(codegen, "_inertia_void_empty_return_guard_decision_8616", None)
        == _postprocess_stage._VoidEmptyReturnGuardDecision8616.PRUNE.value
    )


def test_void_empty_return_guard_void_evidence_from_structured_prototype():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            prototype=None,
            statements=structured_c.CStatements([], codegen=c_codegen),
        ),
        _inertia_current_function_8616=SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimTypeBottom(label="void")),
            info={"x86_16_annotations": {"source_lines": ("void DrawTime(int iCurrentRow)",)}},
        ),
    )

    assert _postprocess_stage._codegen_has_explicit_void_return_8616(SimpleNamespace(), codegen) is True


def test_void_empty_return_guard_prunes_surplus_non_jcc_noop_if(monkeypatch):
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    real_cond = structured_c.CVariable(
        SimRegisterVariable(0x10, 2, name="real_cond"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond = structured_c.CVariable(
        SimRegisterVariable(0x12, 2, name="mul_tmp"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond.tags = {"ins_addr": 0x2000, "vex_block_addr": 0x1FF0}
    real_if = structured_c.CIfElse(
        [
            (
                real_cond,
                structured_c.CStatements(
                    [structured_c.CFunctionCall("Sleep", None, [], codegen=c_codegen)], codegen=c_codegen
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    artifact_if = structured_c.CIfElse(
        [
            (
                artifact_cond,
                structured_c.CStatements(
                    [
                        structured_c.CStatements([], codegen=c_codegen),
                        structured_c.CStatements([], codegen=c_codegen),
                    ],
                    codegen=c_codegen,
                ),
            )
        ],
        else_node=structured_c.CStatements([], codegen=c_codegen),
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    tail_call = structured_c.CFunctionCall("Beep", None, [], codegen=c_codegen)
    root = structured_c.CStatements([real_if, artifact_if, tail_call], codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            prototype=None,
            statements=root,
        ),
        _inertia_current_function_8616=SimpleNamespace(prototype=SimpleNamespace(returnty=SimTypeBottom(label="void"))),
    )
    monkeypatch.setattr(_postprocess_stage, "_real_conditional_branch_count_for_codegen_8616", lambda *_args: 1)
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda *_args, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="imul"),))
            )
        )
    )

    changed = _postprocess_stage._prune_surplus_void_empty_return_guards_8616(project, codegen)

    assert changed is True
    assert root.statements == [real_if, tail_call]
    assert getattr(codegen, "_inertia_void_empty_return_guard_noop_pruned_8616", 0) == 1


def test_void_empty_return_guard_collapses_identical_assignment_arms(monkeypatch):
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    real_cond = structured_c.CVariable(
        SimRegisterVariable(0x10, 2, name="real_cond"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond = structured_c.CVariable(
        SimRegisterVariable(0x12, 2, name="mul_flags"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond.tags = {"ins_addr": 0x2000, "vex_block_addr": 0x1FF0}
    real_if = structured_c.CIfElse(
        [
            (
                real_cond,
                structured_c.CStatements(
                    [structured_c.CFunctionCall("Sleep", None, [], codegen=c_codegen)],
                    codegen=c_codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(0x14, 2, name="mul_result"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    value = structured_c.CBinaryOp(
        "Mul",
        carrier,
        structured_c.CConstant(60, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    true_assignment = structured_c.CAssignment(carrier, value, codegen=c_codegen)
    false_assignment = structured_c.CAssignment(carrier, value, codegen=c_codegen)
    artifact_if = structured_c.CIfElse(
        [
            (
                artifact_cond,
                structured_c.CStatements([true_assignment], codegen=c_codegen),
            )
        ],
        else_node=structured_c.CStatements([false_assignment], codegen=c_codegen),
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    tail_call = structured_c.CFunctionCall("Beep", None, [], codegen=c_codegen)
    root = structured_c.CStatements([real_if, artifact_if, tail_call], codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            prototype=None,
            statements=root,
        ),
        _inertia_current_function_8616=SimpleNamespace(
            prototype=SimpleNamespace(returnty=SimTypeBottom(label="void")),
        ),
    )
    monkeypatch.setattr(
        _postprocess_stage,
        "_real_conditional_branch_count_for_codegen_8616",
        lambda *_args: 1,
    )
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda *_args, **_kwargs: SimpleNamespace(
                capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="imul"),)),
            ),
        ),
    )

    changed = _postprocess_stage._prune_surplus_void_empty_return_guards_8616(
        project,
        codegen,
    )

    assert changed is True
    assert root.statements == [real_if, true_assignment, tail_call]
    assert (
        codegen._inertia_void_empty_return_guard_identical_arms_collapsed_8616
        == 1
    )


def test_empty_return_branch_refuses_ordered_value_for_non_jcc_condition_tag(monkeypatch):
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    real_cond = structured_c.CVariable(
        SimRegisterVariable(0x10, 2, name="real_cond"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond = structured_c.CVariable(
        SimRegisterVariable(0x12, 2, name="mul_tmp"),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact_cond.tags = {"ins_addr": 0x2000, "vex_block_addr": 0x1FF0}
    real_if = structured_c.CIfElse(
        [
            (
                real_cond,
                structured_c.CStatements(
                    [structured_c.CFunctionCall("Sleep", None, [], codegen=c_codegen)],
                    codegen=c_codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    artifact_body = structured_c.CStatements([], codegen=c_codegen)
    artifact_if = structured_c.CIfElse(
        [(artifact_cond, artifact_body)],
        else_node=structured_c.CStatements([], codegen=c_codegen),
        cstyle_ifs=True,
        codegen=c_codegen,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([real_if, artifact_if], codegen=c_codegen),
        )
    )
    project = SimpleNamespace()
    monkeypatch.setattr(
        _postprocess_stage,
        "_linear_function_insns_for_codegen_8616",
        lambda *_args: (SimpleNamespace(address=0x2000, mnemonic="imul"),),
    )
    monkeypatch.setattr(_postprocess_stage, "_ordered_conditional_return_values_8616", lambda *_args: [75])

    changed = _postprocess_stage._materialize_empty_if_return_branches_8616(project, codegen)

    assert changed is False
    assert artifact_body.statements == []
    assert codegen._inertia_empty_return_branch_stats_8616["candidates"] == 1
    assert codegen._inertia_empty_return_branch_stats_8616["materialized"] == 0


def test_decompiler_return_compat_infers_c_return_value_from_terminal_ax_stack_load():
    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

    arch = Arch86_16()
    bp = ailment.Expr.Register(1, arch.registers["bp"][0], 16, reg_name="bp", ins_addr=0x100B4)
    two = ailment.Expr.Const(2, 2, 16, ins_addr=0x100B4)
    bp_minus_two = ailment.Expr.BinaryOp(3, "Sub", [bp, two], bits=16, ins_addr=0x100B4)
    stack_load = ailment.Expr.Load(4, bp_minus_two, 2, arch.memory_endness, ins_addr=0x100B4)
    ax = ailment.Expr.Register(5, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B4)
    assignment = ailment.Stmt.Assignment(6, ax, stack_load, ins_addr=0x100B4)
    ret_stmt = ailment.Stmt.Return(7, [], ins_addr=0x100BF)
    block = SimpleNamespace(statements=[assignment, ret_stmt])
    function = SimpleNamespace(
        addr=0x1000,
        graph=_FakeGraph(block),
        info={"x86_16_annotations": {"stack_vars": {-4: {"name": "mask"}}}},
    )
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), _func=function, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    mask_var = SimStackVariable(-4, 2, base="bp", name="mask", region=0x1000)
    mask_cvar = structured_c.CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(variables_in_use={mask_var: mask_cvar}, unified_local_vars={})

    retval = _infer_x86_16_c_return_value_from_ax_8616(codegen)

    assert retval is mask_cvar
    assert getattr(function, "_inertia_return_compat_c_ast_materialized_count", 0) == 1


def test_terminal_stack_arg_expr_does_not_create_fake_arg_for_positive_bp_offset_without_evidence():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        variables_in_use={},
        unified_local_vars={},
        functy=SimTypeFunction([], SimTypeShort(False), arg_names=()).with_arch(arch),
    )

    expr = _postprocess_stage._terminal_stack_arg_expr_8616(project, codegen, 3, 2)

    assert isinstance(expr, structured_c.CVariable)
    assert isinstance(expr.variable, SimStackVariable)
    assert _postprocess_stage._canonical_stack_offset_8616(expr.variable.offset) == 3
    assert expr.variable.name.startswith("local_")
    assert codegen.cfunc.arg_list == ()
    assert len(getattr(codegen.cfunc, "variables_in_use", {})) == 1


def test_terminal_stack_arg_expr_reuses_existing_stack_slot_for_positive_offset():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    local_var = SimStackVariable(6, 2, base="bp", name="v_6", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        variables_in_use={local_var: local_cvar},
        unified_local_vars={},
        functy=SimTypeFunction([], SimTypeShort(False), arg_names=()).with_arch(arch),
    )

    expr = _postprocess_stage._terminal_stack_arg_expr_8616(project, codegen, 6, 2)

    assert isinstance(expr, structured_c.CVariable)
    assert isinstance(expr.variable, SimStackVariable)
    assert expr.variable.name == local_var.name


def test_terminal_stack_arg_expr_uses_prototype_arg_offsets():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    proto = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False), arg_names=["a", "b"]
    ).with_arch(arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        variables_in_use={},
        unified_local_vars={},
        prototype=proto,
    )

    expr = _postprocess_stage._terminal_stack_arg_expr_8616(project, codegen, 4, 2)

    assert isinstance(expr, structured_c.CVariable)
    assert isinstance(expr.variable, SimStackVariable)
    assert expr.variable.name == "a"
    assert expr.variable.offset == 4
    assert len(getattr(codegen.cfunc, "arg_list", ())) == 1
    assert getattr(codegen.cfunc.arg_list[0].variable, "offset", None) == 4


def test_terminal_stack_arg_expr_applies_prototype_name_to_existing_stack_slot():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arg_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    proto = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False), arg_names=["iTop"]).with_arch(arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        variables_in_use={arg_var: arg_cvar},
        unified_local_vars={},
        prototype=proto,
    )

    expr = _postprocess_stage._terminal_stack_arg_expr_8616(project, codegen, 4, 2)

    assert isinstance(expr, structured_c.CVariable)
    assert isinstance(expr.variable, SimStackVariable)
    assert expr.variable.name == "iTop"
    assert arg_var.name == "iTop"


def test_missing_terminal_ax_return_replaces_segmented_artifact_with_direct_global_load():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    seg = structured_c.CVariable(
        SimRegisterVariable(20, 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    segmented_addr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Mul",
            seg,
            structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(0x48, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    bad_return = structured_c.CReturn(
        structured_c.CUnaryOp("Dereference", segmented_addr, codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements([bad_return], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
        functy=SimTypeFunction([], SimTypeShort(False)).with_arch(arch),
    )
    mov_ax_direct = SimpleNamespace(
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=1, reg=1),
            SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=0, index=0, disp=0x48)),
        ),
        reg_name=lambda reg: "ax" if reg == 1 else "",
    )
    ret = SimpleNamespace(mnemonic="ret", operands=(), reg_name=lambda _reg: "")
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(mov_ax_direct, ret)))
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, prototype=codegen.cfunc.functy)
    cod_metadata = SimpleNamespace(
        cod_raw_entries=(
            {"text": "mov\tax,WORD PTR _g_work+10"},
            {"text": "add\tax,WORD PTR _g_work"},
        )
    )
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda *_args, **_kwargs: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda *_args, **_kwargs: function)),
        _inertia_cod_metadata_by_func_addr_8616={0x1000: cod_metadata},
    )
    codegen.project = project

    changed = _materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is True
    assert root.statements[-1] is bad_return
    assert isinstance(bad_return.retval, structured_c.CVariable)
    assert isinstance(bad_return.retval.variable, SimMemoryVariable)
    assert bad_return.retval.variable.addr == 0x48


def test_missing_terminal_ax_return_materializes_direct_global_add_return():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    seg = structured_c.CVariable(
        SimRegisterVariable(20, 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bad_return = structured_c.CReturn(
        structured_c.CBinaryOp(
            "Add",
            structured_c.CFunctionCall(
                "SEG_U16",
                None,
                [seg, structured_c.CConstant(0x4E, SimTypeShort(False), codegen=codegen)],
                codegen=codegen,
            ),
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="vvar_58"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = structured_c.CStatements([bad_return], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
        functy=SimTypeFunction([], SimTypeShort(False)).with_arch(arch),
    )
    mov_ax_direct = SimpleNamespace(
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=1, reg=1),
            SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=0, index=0, disp=0x4E)),
        ),
        reg_name=lambda reg: "ax" if reg == 1 else "",
    )
    add_ax_direct = SimpleNamespace(
        mnemonic="add",
        operands=(
            SimpleNamespace(type=1, reg=1),
            SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=0, index=0, disp=0x44)),
        ),
        reg_name=lambda reg: "ax" if reg == 1 else "",
    )
    ret = SimpleNamespace(mnemonic="ret", operands=(), reg_name=lambda _reg: "")
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(mov_ax_direct, add_ax_direct, ret)))
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, prototype=codegen.cfunc.functy)
    cod_metadata = SimpleNamespace(
        cod_raw_entries=(
            {"text": "mov\tax,WORD PTR _g_work+10"},
            {"text": "add\tax,WORD PTR _g_work"},
        )
    )
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda *_args, **_kwargs: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda *_args, **_kwargs: function)),
        _inertia_cod_metadata_by_func_addr_8616={0x1000: cod_metadata},
    )
    codegen.project = project

    changed = _materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is True
    assert root.statements[-1] is bad_return
    assert isinstance(bad_return.retval, structured_c.CBinaryOp)
    assert bad_return.retval.op == "Add"
    assert isinstance(bad_return.retval.lhs, structured_c.CVariable)
    assert isinstance(bad_return.retval.rhs, structured_c.CVariable)
    assert bad_return.retval.lhs.variable.name == "g_004E"
    assert bad_return.retval.rhs.variable.name == "g_0044"


def test_missing_terminal_ax_return_replaces_artifact_with_ax_byte_pair_from_binary_evidence():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    a_arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x1000),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    b_arg = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x1000),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    temp = structured_c.CVariable(
        SimRegisterVariable(0, 1, name="v5"),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    bad_return = structured_c.CReturn(
        structured_c.CBinaryOp("Add", temp, a_arg, codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(temp, b_arg, codegen=codegen),
            bad_return,
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        arg_list=[a_arg, b_arg],
        variables_in_use={},
        unified_local_vars={},
        functy=SimTypeFunction(
            [SimTypeChar(True), SimTypeChar(True)],
            SimTypeChar(True),
            arg_names=["a", "b"],
        ).with_arch(arch),
    )
    mov_al_b = SimpleNamespace(
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=1, reg=1),
            SimpleNamespace(type=3, size=1, mem=SimpleNamespace(base=2, index=0, disp=6)),
        ),
        reg_name=lambda reg: {1: "al", 2: "bp"}.get(reg, ""),
    )
    mov_ah_a = SimpleNamespace(
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=1, reg=3),
            SimpleNamespace(type=3, size=1, mem=SimpleNamespace(base=2, index=0, disp=4)),
        ),
        reg_name=lambda reg: {2: "bp", 3: "ah"}.get(reg, ""),
    )
    ret = SimpleNamespace(mnemonic="ret", operands=(), reg_name=lambda _reg: "")
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(mov_al_b, mov_ah_a, ret)))
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, prototype=codegen.cfunc.functy)
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda *_args, **_kwargs: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda *_args, **_kwargs: function)),
    )
    codegen.project = project

    changed = _materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is True
    assert root.statements[-1] is bad_return
    assert isinstance(bad_return.retval, structured_c.CBinaryOp)
    assert bad_return.retval.op == "Or"
    assert bad_return.retval.lhs.op == "And"
    assert bad_return.retval.rhs.op == "Shl"


def test_decompiler_return_compat_uses_latest_ail_insn_when_c_return_has_no_ail_return():
    class _FakeGraph:
        def __init__(self, block):
            self._block = block

        def nodes(self):
            return [self._block]

    arch = Arch86_16()
    bp = ailment.Expr.Register(1, arch.registers["bp"][0], 16, reg_name="bp", ins_addr=0x100B4)
    two = ailment.Expr.Const(2, 2, 16, ins_addr=0x100B4)
    bp_minus_two = ailment.Expr.BinaryOp(3, "Sub", [bp, two], bits=16, ins_addr=0x100B4)
    stack_load = ailment.Expr.Load(4, bp_minus_two, 2, arch.memory_endness, ins_addr=0x100B4)
    ax = ailment.Expr.Register(5, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x100B4)
    assignment = ailment.Stmt.Assignment(6, ax, stack_load, ins_addr=0x100B4)
    sp = ailment.Expr.Register(7, arch.registers["sp"][0], 16, reg_name="sp", ins_addr=0x100BF)
    epilogue = ailment.Stmt.Assignment(8, sp, sp, ins_addr=0x100BF)
    block = SimpleNamespace(statements=[assignment, epilogue])
    function = SimpleNamespace(addr=0x1000, graph=None, info={})
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch), _func=function, ail_graph=_FakeGraph(block), next_idx=lambda _name: 1, 
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    mask_var = SimStackVariable(-4, 2, base="bp", name="mask", region=0x1000)
    mask_cvar = structured_c.CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(variables_in_use={mask_var: mask_cvar}, unified_local_vars={})

    retval = _infer_x86_16_c_return_value_from_ax_8616(codegen)

    assert retval is mask_cvar


def test_duplicate_word_increment_shift_expr_collapses_to_word_increment():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    source_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)

    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    alias_map = {
        id(low_tmp_var): source_cvar,
        id(high_tmp_var): source_cvar,
    }

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return alias_map.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert isinstance(matched, structured_c.CBinaryOp)
    assert matched.op == "Add"
    assert matched.lhs.variable is source_var
    assert matched.rhs.value == 1


def test_duplicate_word_increment_shift_expr_rejects_mismatched_storage_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    left_var = SimStackVariable(4, 2, base="bp", name="left", region=0x1000)
    right_var = SimStackVariable(6, 2, base="bp", name="right", region=0x1000)
    low_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(10, 1, base="bp", name="ir_4", region=0x1000)

    left_cvar = structured_c.CVariable(left_var, variable_type=SimTypeShort(False), codegen=codegen)
    right_cvar = structured_c.CVariable(right_var, variable_type=SimTypeShort(False), codegen=codegen)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    alias_map = {
        id(low_tmp_var): left_cvar,
        id(high_tmp_var): right_cvar,
    }

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return alias_map.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert matched is None


def test_adjacent_byte_pair_alias_seed_widens_into_one_word():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CConstant(0x2000, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CConstant(0x2001, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )

    aliases = decompile._seed_adjacent_byte_pair_aliases(codegen.project, codegen)

    assert id(low_tmp_var) in aliases
    assert id(high_tmp_var) in aliases
    assert decompile._same_c_expression(aliases[id(low_tmp_var)], aliases[id(high_tmp_var)])
    assert isinstance(aliases[id(low_tmp_var)], structured_c.CUnaryOp)
    assert getattr(aliases[id(low_tmp_var)], "op", None) == "Dereference"

    def resolve_copy_alias_expr(expr):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return expr
        return aliases.get(id(variable), expr)

    expr = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = decompile._match_duplicate_word_increment_shift_expr(expr, resolve_copy_alias_expr, codegen)

    assert isinstance(matched, structured_c.CBinaryOp)
    assert matched.op == "Add"
    assert isinstance(matched.lhs, structured_c.CUnaryOp)
    assert getattr(matched.lhs, "op", None) == "Dereference"
    assert matched.rhs.value == 1


def test_adjacent_byte_pair_alias_seed_preserves_dereferenced_source_evidence():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    low_tmp_var = SimStackVariable(6, 1, base="bp", name="ir_3", region=0x1000)
    high_tmp_var = SimStackVariable(8, 1, base="bp", name="ir_4", region=0x1000)
    source_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp(
        "Dereference", structured_c.CTypeCast(None, SimTypeShort(False), source_cvar, codegen=codegen), codegen=codegen
    )
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CBinaryOp(
                "Add", source_cvar, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())
    deref_source = structured_c.CUnaryOp("Dereference", source_cvar, codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
                structured_c.CAssignment(source_cvar, deref_source, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )

    aliases = decompile._seed_adjacent_byte_pair_aliases(codegen.project, codegen)

    assert not (
        id(low_tmp_var) in aliases
        and id(high_tmp_var) in aliases
        and decompile._same_c_expression(aliases[id(low_tmp_var)], aliases[id(high_tmp_var)])
    )


def test_linear_recurrence_keeps_dereference_based_byte_pair_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    low_tmp_var = SimRegisterVariable(10, 1, name="ir_3")
    high_tmp_var = SimRegisterVariable(12, 1, name="ir_4")
    recur_var = SimRegisterVariable(14, 2, name="ir_5")
    source_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)

    low_tmp = structured_c.CVariable(low_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_tmp = structured_c.CVariable(high_tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    recur_cvar = structured_c.CVariable(recur_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_cvar = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)

    low_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, SimTypeShort(False), source_cvar, codegen=codegen),
        codegen=codegen,
    )
    object.__setattr__(low_load, "_type", SimTypeChar())
    high_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            None,
            SimTypeShort(False),
            structured_c.CBinaryOp(
                "Add",
                source_cvar,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    object.__setattr__(high_load, "_type", SimTypeChar())

    widened = structured_c.CBinaryOp(
        "Shr",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Or",
                low_tmp,
                structured_c.CBinaryOp(
                    "Mul",
                    high_tmp,
                    structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(low_tmp, low_load, codegen=codegen),
                structured_c.CAssignment(high_tmp, high_load, codegen=codegen),
                structured_c.CAssignment(recur_cvar, widened, codegen=codegen),
                structured_c.CIfElse(
                    [
                        (
                            structured_c.CUnaryOp("Not", recur_cvar, codegen=codegen),
                            structured_c.CStatements([], addr=0x1000, codegen=codegen),
                        )
                    ],
                    codegen=codegen,
                ),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    recur_stmt = codegen.cfunc.statements.statements[2]
    assert isinstance(recur_stmt, structured_c.CAssignment)
    assert isinstance(recur_stmt.rhs, structured_c.CBinaryOp)
    assert recur_stmt.rhs.op == "Add"
    assert isinstance(recur_stmt.rhs.lhs, structured_c.CUnaryOp)
    assert getattr(recur_stmt.rhs.lhs, "op", None) == "Dereference"
    rewritten_if = codegen.cfunc.statements.statements[3]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    rewritten_cond = rewritten_if.condition_and_nodes[0][0]
    assert isinstance(rewritten_cond, structured_c.CUnaryOp)
    assert rewritten_cond.op == "Not"
    # operand may be CBinaryOp (pre-lowering) or CVariable (post-lowering via
    # stack alias resolution). Both shapes preserve the recurrence evidence.
    assert isinstance(rewritten_cond.operand, (structured_c.CBinaryOp, structured_c.CVariable))


def test_linear_recurrence_preserves_stack_byte_pair_evidence_for_assignments_and_conditions():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    temp_var = SimRegisterVariable(10, 2, name="ir_3")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    condition = structured_c.CUnaryOp("Not", widened_word, codegen=codegen)
    body = structured_c.CStatements([], addr=0x1000, codegen=codegen)
    if_stmt = structured_c.CIfElse([(condition, body)], codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(temp_cvar, widened_word, codegen=codegen),
                if_stmt,
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert not changed
    first_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(first_stmt, structured_c.CAssignment)
    assert isinstance(first_stmt.rhs, structured_c.CBinaryOp)
    assert first_stmt.rhs.op == "Add"
    assert isinstance(first_stmt.rhs.lhs, structured_c.CBinaryOp)
    assert first_stmt.rhs.lhs.op == "Or"
    assert first_stmt.rhs.rhs.value == 1
    rewritten_if = codegen.cfunc.statements.statements[1]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    rewritten_cond = rewritten_if.condition_and_nodes[0][0]
    assert isinstance(rewritten_cond, structured_c.CUnaryOp)
    assert rewritten_cond.op == "Not"
    assert isinstance(rewritten_cond.operand, structured_c.CBinaryOp)
    assert rewritten_cond.operand.op == "Add"
    assert isinstance(rewritten_cond.operand.lhs, structured_c.CBinaryOp)
    assert rewritten_cond.operand.lhs.op == "Or"
    assert rewritten_cond.operand.rhs.value == 1


def test_linear_recurrence_refuses_to_linearize_loaded_byte_value_back_into_ds_address():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    temp_var = SimRegisterVariable(14, 2, name="vvar_173")

    ds_cvar = structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    addr_expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Shl",
            ds_cvar,
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(2987, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    byte_deref = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
    object.__setattr__(byte_deref, "_type", SimTypeChar())

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(
                    temp_cvar,
                    structured_c.CBinaryOp(
                        "Add",
                        byte_deref,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CAssignment(
                    byte_deref,
                    structured_c.CBinaryOp(
                        "Sub",
                        temp_cvar,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    store_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(store_stmt, structured_c.CAssignment)
    assert isinstance(store_stmt.rhs, structured_c.CBinaryOp)
    assert store_stmt.rhs.op == "Sub"
    assert isinstance(store_stmt.rhs.lhs, structured_c.CVariable)
    assert getattr(store_stmt.rhs.lhs, "variable", None) is temp_var


def test_structured_simplifier_preserves_adjacent_ds_byte_loads_and_word_increment_value():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10CE0,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    low_temp_var = SimRegisterVariable(1, 1, name="ir_10")
    high_temp_var = SimRegisterVariable(2, 1, name="ir_11")

    def ds_linear_expr():
        return structured_c.CBinaryOp(
            "Shl",
            structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_linear_expr(),
            structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    low_load = structured_c.CAssignment(
        structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2986), SimTypeChar(False)),
        codegen=codegen,
    )
    high_load = structured_c.CAssignment(
        structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2987), SimTypeChar(False)),
        codegen=codegen,
    )
    widened_increment = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = structured_c.CAssignment(
        deref(ds_addr(2986), SimTypeShort(False)),
        widened_increment,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [low_load, high_load, word_store],
        addr=0x10CE0,
        codegen=codegen,
    )

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True

    rewritten_low_load = codegen.cfunc.statements.statements[0]
    rewritten_high_load = codegen.cfunc.statements.statements[1]
    rewritten_store = codegen.cfunc.statements.statements[2]

    assert isinstance(rewritten_low_load.rhs, structured_c.CUnaryOp)
    assert isinstance(rewritten_high_load.rhs, structured_c.CUnaryOp)
    assert rewritten_low_load.rhs.operand.rhs.value == 2986
    assert rewritten_high_load.rhs.operand.rhs.value == 2987

    assert isinstance(rewritten_store.rhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.op == "Add"
    assert isinstance(rewritten_store.rhs.lhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.lhs.op == "Or"
    assert rewritten_store.rhs.rhs.value == 1


def test_structured_simplifier_refuses_bare_word_global_promotion_for_adjacent_memory_bytes():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    low_global = structured_c.CVariable(
        SimMemoryVariable(0x0BA4, 1, name="g_0BA4", region=0x10808),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high_global = structured_c.CVariable(
        SimMemoryVariable(0x0BA5, 1, name="g_0BA5", region=0x10808),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )

    expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            low_global,
            structured_c.CBinaryOp(
                "Shl",
                high_global,
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = expr

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    result = codegen.cfunc.statements
    assert isinstance(result, structured_c.CBinaryOp)
    assert result.op == "Add"
    assert isinstance(result.lhs, structured_c.CBinaryOp)
    assert result.lhs.op == "Or"
    assert isinstance(result.lhs.lhs, structured_c.CVariable)
    assert isinstance(result.lhs.lhs.variable, SimMemoryVariable)
    assert result.lhs.lhs.variable.size == 1


def test_structured_simplifier_keeps_dereference_backed_temp_widening_honest():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    low_temp_var = SimRegisterVariable(101, 1, name="ir_8")
    high_temp_var = SimRegisterVariable(102, 1, name="ir_9")

    def ds_linear_expr():
        return structured_c.CBinaryOp(
            "Shl",
            structured_c.CVariable(ds_var, variable_type=SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_linear_expr(),
            structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def ds_addr_plus_one(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            ds_addr(offset),
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    low_load = structured_c.CAssignment(
        structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr(2980), SimTypeChar(False)),
        codegen=codegen,
    )
    high_load = structured_c.CAssignment(
        structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
        deref(ds_addr_plus_one(2980), SimTypeChar(False)),
        codegen=codegen,
    )
    widened_increment = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            structured_c.CVariable(low_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CVariable(high_temp_var, variable_type=SimTypeChar(False), codegen=codegen),
                structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = structured_c.CAssignment(
        deref(ds_addr(2980), SimTypeShort(False)),
        widened_increment,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [low_load, high_load, word_store],
        addr=0x10808,
        codegen=codegen,
    )

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rewritten_store = codegen.cfunc.statements.statements[2]
    assert isinstance(rewritten_store.rhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.op == "Add"
    assert isinstance(rewritten_store.rhs.lhs, structured_c.CBinaryOp)
    assert rewritten_store.rhs.lhs.op == "Or"
    assert isinstance(rewritten_store.rhs.lhs.lhs, structured_c.CVariable)
    assert rewritten_store.rhs.lhs.lhs.variable is low_temp_var
    assert rewritten_store.rhs.rhs.value == 1


def test_structured_simplifier_does_not_rewrite_inside_dereference_address_subtrees():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self.stmt_comments = {}
            self.expr_comments = {}
            self.display_vvar_ids = False
            self.cfunc = SimpleNamespace(
                addr=0x10808,
                arg_list=(),
                sort_local_vars=lambda: None,
                unified_local_vars={},
                variables_in_use={},
            )

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds_var = SimRegisterVariable(ds_offset, ds_size, name="ds")
    row_var = SimStackVariable(2, 2, base="bp", name="s_2", region=0x10808)
    ax_var = SimRegisterVariable(120, 2, name="ax_3")
    bx_var = SimRegisterVariable(122, 2, name="bx")

    def cvar(var, type_=None):
        return structured_c.CVariable(var, variable_type=type_, codegen=codegen)

    def const(value):
        return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)

    def ds_linear():
        return structured_c.CBinaryOp("Shl", cvar(ds_var, SimTypeShort(False)), const(4), codegen=codegen)

    def row_index():
        return structured_c.CBinaryOp("Shl", cvar(row_var, SimTypeShort(False)), const(1), codegen=codegen)

    def ds_indexed(offset: int):
        return structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp("Add", ds_linear(), const(offset), codegen=codegen),
            row_index(),
            codegen=codegen,
        )

    def deref(addr_expr, type_):
        node = structured_c.CUnaryOp("Dereference", addr_expr, codegen=codegen)
        object.__setattr__(node, "_type", type_)
        return node

    ax_load = structured_c.CAssignment(
        cvar(ax_var, SimTypeShort(False)),
        structured_c.CBinaryOp(
            "Or",
            deref(ds_indexed(2890), SimTypeChar(False)),
            structured_c.CBinaryOp(
                "Shl",
                deref(
                    structured_c.CBinaryOp("Add", ds_indexed(2890), const(1), codegen=codegen),
                    SimTypeChar(False),
                ),
                const(8),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    bx_assign = structured_c.CAssignment(cvar(bx_var, SimTypeShort(False)), row_index(), codegen=codegen)
    word_store = structured_c.CAssignment(
        deref(
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp("Add", ds_linear(), const(2892), codegen=codegen),
                cvar(bx_var, SimTypeShort(False)),
                codegen=codegen,
            ),
            SimTypeShort(False),
        ),
        structured_c.CBinaryOp(
            "Or",
            deref(ds_indexed(2890), SimTypeChar(False)),
            structured_c.CBinaryOp(
                "Shl",
                deref(
                    structured_c.CBinaryOp("Add", ds_indexed(2890), const(1), codegen=codegen),
                    SimTypeChar(False),
                ),
                const(8),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([ax_load, bx_assign, word_store], addr=0x10808, codegen=codegen)

    changed = decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rewritten_load = codegen.cfunc.statements.statements[0]
    rewritten_store = codegen.cfunc.statements.statements[2]

    assert rewritten_load.rhs.lhs.operand.rhs.value == 2890
    assert rewritten_load.rhs.rhs.lhs.operand.lhs.rhs.value == 2890
    assert rewritten_store.lhs.operand.lhs.rhs.value == 2892
    assert rewritten_store.rhs.lhs.operand.rhs.value == 2890
    assert rewritten_store.rhs.rhs.lhs.operand.lhs.rhs.value == 2890


def test_linear_recurrence_assignment_rewrite_refuses_non_dereference_algebraic_shape():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    temp_var = SimRegisterVariable(10, 2, name="ir_9")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [structured_c.CAssignment(temp_cvar, widened_word, codegen=codegen)],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, structured_c.CAssignment)
    assert isinstance(stmt.rhs, structured_c.CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert isinstance(stmt.rhs.lhs, structured_c.CBinaryOp)
    assert stmt.rhs.lhs.op == "Or"
    assert stmt.rhs.rhs.value == 1


def test_linear_recurrence_condition_rewrite_refuses_non_dereference_algebraic_shape():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    base_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    widened_word = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Or",
            base_cvar,
            structured_c.CBinaryOp(
                "Mul",
                base_cvar,
                structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    while_stmt = structured_c.CWhileLoop(
        structured_c.CUnaryOp("Not", widened_word, codegen=codegen),
        structured_c.CStatements([], addr=0x1000, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([while_stmt], addr=0x1000, codegen=codegen),
    )

    changed = decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)

    assert changed is False
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, structured_c.CWhileLoop)
    assert isinstance(rewritten.condition, structured_c.CUnaryOp)
    assert rewritten.condition.op == "Not"
    assert isinstance(rewritten.condition.operand, structured_c.CBinaryOp)
    assert rewritten.condition.operand.op == "Add"
    assert isinstance(rewritten.condition.operand.lhs, structured_c.CBinaryOp)
    assert rewritten.condition.operand.lhs.op == "Or"
    assert rewritten.condition.operand.rhs.value == 1


def test_linear_recurrence_tolerates_self_referential_condition_nodes():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    temp_var = SimRegisterVariable(10, 2, name="ir_7")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cyclic_cond = structured_c.CUnaryOp("Not", temp_cvar, codegen=codegen)
    cyclic_cond.operand = cyclic_cond

    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements(
            [
                structured_c.CIfElse(
                    [(cyclic_cond, structured_c.CStatements([], addr=0x1000, codegen=codegen))],
                    codegen=codegen,
                )
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    decompile._coalesce_linear_recurrence_statements(codegen.project, codegen)
    rewritten_if = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_if, structured_c.CIfElse)
    assert rewritten_if.condition_and_nodes[0][0] is cyclic_cond


def test_canonicalize_stack_cvar_expr_prefers_annotated_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    alias_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[arg_cvar],
        variables_in_use={
            arg_var: arg_cvar,
            alias_var: alias_cvar,
        },
    )

    expr = structured_c.CBinaryOp(
        "Add",
        alias_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CBinaryOp)
    assert canonical.lhs.variable is arg_var
    assert canonical.rhs.value == 1
    assert decompile._canonicalize_stack_cvar_expr(alias_cvar, codegen).variable is arg_var


def test_canonicalize_stack_cvars_skips_invalid_assignment_lhs_forms():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    slot_var = SimStackVariable(4, 2, base="bp", name="a", region=0x1000)
    slot_cvar = structured_c.CVariable(slot_var, variable_type=SimTypeShort(False), codegen=codegen)
    bad_lhs = structured_c.CBinaryOp(
        "Sub",
        slot_cvar,
        structured_c.CConstant(2, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
    )

    assignment = structured_c.CAssignment(
        bad_lhs,
        slot_cvar,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={slot_var: slot_cvar},
        statements=structured_c.CStatements([assignment], addr=0x1000, codegen=codegen),
    )

    changed = _cli_stack_cvars._canonicalize_stack_cvars(
        codegen,
        replace_c_children=_replace_c_children_8616,
        canonicalize_stack_cvar_expr=decompile._canonicalize_stack_cvar_expr,
    )

    assert changed is False
    assert isinstance(codegen.cfunc.statements.statements[0], structured_c.CAssignment)
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten.lhs, structured_c.CBinaryOp)
    assert isinstance(rewritten.lhs.lhs, structured_c.CVariable)
    assert rewritten.lhs.lhs.variable is slot_var


def test_canonicalize_stack_cvars_keeps_simple_lvalue_canonicalization():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    alias_var = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    assignment = structured_c.CAssignment(alias_cvar, arg_cvar, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[arg_cvar],
        variables_in_use={arg_var: arg_cvar, alias_var: alias_cvar},
        statements=structured_c.CStatements([assignment], addr=0x1000, codegen=codegen),
    )

    _cli_stack_cvars._canonicalize_stack_cvars(
        codegen,
        replace_c_children=_replace_c_children_8616,
        canonicalize_stack_cvar_expr=decompile._canonicalize_stack_cvar_expr,
    )

    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, structured_c.CAssignment)
    rewritten_var = getattr(rewritten.lhs, "variable", None)
    assert isinstance(rewritten_var, SimStackVariable)
    assert rewritten_var.base == "bp"
    assert rewritten_var.offset == 4


def test_canonicalize_stack_cvar_expr_rewrites_indexed_stack_reference_to_exact_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6", region=0x1000)
    target_var = SimStackVariable(2, 2, base="bp", name="wait_hi", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeChar(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )

    expr = structured_c.CUnaryOp(
        "Reference",
        structured_c.CIndexedVariable(
            structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CUnaryOp)
    assert canonical.op == "Reference"
    assert isinstance(canonical.operand, structured_c.CVariable)
    assert canonical.operand.variable is target_var


def test_canonicalize_stack_cvar_expr_collapses_deref_of_reference_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    slot_var = SimStackVariable(0, 2, base="bp", name="goal", region=0x1000)
    slot_cvar = structured_c.CVariable(slot_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(arg_list=[], variables_in_use={slot_var: slot_cvar})

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CUnaryOp("Reference", slot_cvar, codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is slot_cvar


def test_canonicalize_stack_cvar_expr_uses_stack_local_pointer_alias_for_indexed_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    alias_var = SimStackVariable(-2, 2, base="bp", name="s_2", region=0x1000)
    target_var = SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[target_cvar],
        variables_in_use={
            alias_var: alias_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                alias_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", alias_cvar, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CUnaryOp(
            "Reference",
            structured_c.CIndexedVariable(
                structured_c.CUnaryOp("Reference", alias_cvar, codegen=codegen),
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_uses_vvar_pointer_alias_for_direct_indexed_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    base_var = SimStackVariable(-8, 1, base="bp", name="s_8", region=0x1000)
    target_var = SimStackVariable(-11, 1, base="bp", name="local_b", region=0x1000)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeChar(False), codegen=codegen)
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            base_var: base_cvar,
            target_var: target_cvar,
            carrier_var: carrier_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CIndexedVariable(
        carrier_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_vvar_carrier():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(0x20, 2, name="vvar_20")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    base_var = SimStackVariable(-8, 2, base="bp", name="s_8", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-10, 2, base="bp", name="local_a", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            ss_var: ss_cvar,
            carrier_var: carrier_cvar,
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                carrier_cvar,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CVariable)
    assert canonical.variable is target_var


def test_canonicalize_stack_cvar_expr_rewrites_plain_deref_from_vvar_carrier():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    carrier_var = SimRegisterVariable(0x20, 2, name="vvar_11")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    base_var = SimStackVariable(-8, 2, base="bp", name="s_8", region=0x1000)
    base_cvar = structured_c.CVariable(base_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-10, 2, base="bp", name="local_a", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            carrier_var: carrier_cvar,
            base_var: base_cvar,
            target_var: target_cvar,
        },
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier_cvar,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CVariable)
    assert canonical.variable is target_var


def test_canonicalize_stack_cvar_expr_rewrites_indexed_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CIndexedVariable(
        structured_c.CBinaryOp(
            "Add",
            structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
            structured_c.CConstant(-6, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_infers_bare_stack_base_bias_from_bp_slots():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x1000)
    i_parent_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x1000)
    i_cvar = structured_c.CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_parent_cvar = structured_c.CVariable(i_parent_var, variable_type=SimTypeShort(False), codegen=codegen)
    expr_i = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr_i_parent = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            i_var: i_cvar,
            i_parent_var: i_parent_cvar,
        },
        unified_local_vars={},
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(i_cvar, expr_i, codegen=codegen),
                structured_c.CAssignment(i_parent_cvar, expr_i_parent, codegen=codegen),
            ],
            addr=0x1000,
            codegen=codegen,
        ),
    )

    canonical_i = decompile._canonicalize_stack_cvar_expr(expr_i, codegen)
    canonical_i_parent = decompile._canonicalize_stack_cvar_expr(expr_i_parent, codegen)

    assert canonical_i is i_cvar
    assert canonical_i_parent is i_parent_cvar


def test_canonicalize_stack_cvar_expr_rewrites_deref_from_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
            structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_stack_base_fake_variable_to_slot():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={ss_var: ss_cvar, target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements([], addr=0x1000, codegen=codegen)

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
                structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_ss_linear_deref_from_dirty_vvar_stack_alias():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={ss_var: ss_cvar, carrier_var: carrier_cvar, target_var: target_cvar},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
                    structured_c.CConstant(-2, SimTypeShort(True), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                ss_cvar,
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert canonical is target_cvar


def test_canonicalize_stack_cvar_expr_rewrites_arithmetic_from_dirty_vvar_stack_alias():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    ss_off, ss_size = codegen.project.arch.registers["ss"]
    ss_var = SimRegisterVariable(ss_off, ss_size, name="ss")
    ss_cvar = structured_c.CVariable(ss_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_var = SimRegisterVariable(8, 2, name="vvar_24")
    carrier_cvar = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x1000)
    target_cvar = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={
            ss_var: ss_cvar,
            carrier_var: carrier_cvar,
            target_var: target_cvar,
        },
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                carrier_cvar,
                target_cvar,
                codegen=codegen,
            )
        ],
        addr=0x1000,
        codegen=codegen,
    )

    expr = structured_c.CBinaryOp(
        "Sub",
        structured_c.CDirtyExpression(SimpleNamespace(varid=24, name="vvar_24"), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(expr, codegen)

    assert isinstance(canonical, structured_c.CBinaryOp)
    assert isinstance(canonical.lhs, structured_c.CVariable)
    assert getattr(canonical.lhs, "name", None) == "i"


def test_canonicalize_stack_cvar_expr_refuses_dirty_vvar_assignment_cycle():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    var20 = SimRegisterVariable(20, 2, name="vvar_20")
    var21 = SimRegisterVariable(21, 2, name="vvar_21")
    cvar20 = structured_c.CVariable(var20, variable_type=SimTypeShort(False), codegen=codegen)
    cvar21 = structured_c.CVariable(var21, variable_type=SimTypeShort(False), codegen=codegen)
    dirty20 = structured_c.CDirtyExpression(SimpleNamespace(varid=20, name="vvar_20"), codegen=codegen)
    dirty21 = structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="vvar_21"), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={var20: cvar20, var21: cvar21},
        unified_local_vars={},
    )
    dirty20_lhs = structured_c.CDirtyExpression(SimpleNamespace(varid=20, name="vvar_20"), codegen=codegen)
    dirty21_lhs = structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="vvar_21"), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(dirty20_lhs, dirty21, codegen=codegen),
            structured_c.CAssignment(dirty21_lhs, dirty20, codegen=codegen),
        ],
        addr=0x1000,
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(dirty20, codegen)

    assert canonical is dirty20
    assert codegen._inertia_stack_lowering_dirty_cycle_refused_8616 == 1


def test_canonicalize_stack_cvar_expr_refuses_dirty_vvar_depth_explosion():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False
            self._inertia_stack_lowering_canonicalize_max_depth_8616 = 1

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    var20 = SimRegisterVariable(20, 2, name="vvar_20")
    cvar20 = structured_c.CVariable(var20, variable_type=SimTypeShort(False), codegen=codegen)
    dirty20 = structured_c.CDirtyExpression(SimpleNamespace(varid=20, name="vvar_20"), codegen=codegen)
    dirty21 = structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="vvar_21"), codegen=codegen)
    dirty20_lhs = structured_c.CDirtyExpression(SimpleNamespace(varid=20, name="vvar_20"), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        variables_in_use={var20: cvar20},
        unified_local_vars={},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [structured_c.CAssignment(dirty20_lhs, dirty21, codegen=codegen)],
        addr=0x1000,
        codegen=codegen,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(dirty20, codegen)

    assert canonical is dirty21
    assert codegen._inertia_stack_lowering_canonicalize_depth_refused_8616 == 1


def test_materialize_missing_stack_local_declarations_adds_live_stack_slots():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(2, 2, base="bp", name="arg", region=0x1000)
    local_var = SimStackVariable(4, 2, base="bp", name="local", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={
            arg_var: arg_cvar,
            local_var: local_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    assert local_var in codegen.cfunc.unified_local_vars
    assert codegen.cfunc.unified_local_vars[local_var] == {(local_cvar, local_cvar.variable_type)}
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_materialize_missing_stack_local_declarations_syncs_live_stack_name_to_existing_declaration():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    decl_var = SimStackVariable(-4, 2, base="bp", name="local_4", region=0x1000)
    live_var = SimStackVariable(-4, 2, base="bp", name="goal", region=0x1000)
    decl_cvar = structured_c.CVariable(decl_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(
                    live_cvar,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            ],
            codegen=codegen,
        ),
        unified_local_vars={decl_var: {(decl_cvar, decl_cvar.variable_type)}},
        variables_in_use={
            decl_var: decl_cvar,
            live_var: live_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    assert decl_var.name == "goal"
    assert getattr(decl_cvar, "name", None) == "goal"
    assert codegen._inertia_stack_declaration_name_synced_count_8616 == 1


def test_materialize_missing_stack_local_declarations_skips_arg_slot_aliases():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(2, 2, base="bp", name="arg", region=0x1000)
    alias_var = SimStackVariable(2, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    alias_cvar = structured_c.CVariable(alias_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={
            arg_var: arg_cvar,
            alias_var: alias_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is False
    assert alias_var not in codegen.cfunc.unified_local_vars
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_materialize_missing_stack_local_declarations_normalizes_ast_only_negative_arg_placeholder():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    leaked_local_var = SimStackVariable(-8, 2, base="bp", name="arg_6", region=0x1000)
    leaked_local_cvar = structured_c.CVariable(leaked_local_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        leaked_local_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=structured_c.CStatements([stmt], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    assert leaked_local_var.name == "local_8"
    assert getattr(leaked_local_cvar, "name", None) == "local_8"
    assert leaked_local_var in codegen.cfunc.unified_local_vars


def test_materialize_missing_stack_local_declarations_keeps_ast_only_arg_slot_as_argument():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        arg_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([stmt], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is False
    assert arg_var.name == "arg_4"
    assert getattr(arg_cvar, "name", None) == "arg_4"
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_normalize_stack_variable_identifiers_declares_ast_only_generic_local():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    leaked_local_var = SimStackVariable(-8, 2, base="bp", name="arg_6", region=0x1000)
    leaked_local_cvar = structured_c.CVariable(leaked_local_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        leaked_local_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        functy=None,
        statements=structured_c.CStatements([stmt], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
        sort_local_vars=lambda: None,
    )

    _postprocess_stage._normalize_stack_variable_identifiers_8616(codegen)

    assert leaked_local_var.name == "local_8"
    assert getattr(leaked_local_cvar, "name", None) == "local_8"
    assert codegen.cfunc.variables_in_use[leaked_local_var] is leaked_local_cvar
    assert leaked_local_var in codegen.cfunc.unified_local_vars
    assert codegen._inertia_stack_identifier_live_node_declarations_8616 == 1


def test_normalize_stack_variable_identifiers_preserves_annotated_stack_local_name():
    class _Functions:
        def function(self, *, addr, create=False):
            assert addr == 0x1000
            return SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {-4: {"name": "i"}}}})

    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(functions=_Functions()))
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    local_var = SimStackVariable(-4, 2, base="bp", name="local_4", region=0x1000)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        local_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        functy=None,
        statements=structured_c.CStatements([stmt], codegen=codegen),
        unified_local_vars={local_var: {(local_cvar, local_cvar.variable_type)}},
        variables_in_use={local_var: local_cvar},
        sort_local_vars=lambda: None,
    )

    _postprocess_stage._normalize_stack_variable_identifiers_8616(codegen)

    assert local_var.name == "i"
    assert getattr(local_cvar, "name", None) == "i"


def test_materialize_missing_stack_local_declarations_converts_stack_bp_placeholder_variable():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _FakeCodegen()
    placeholder_var = SimRegisterVariable(0, 2, name="<0x1000[is_1]|Stack bp-0x6, 1 B>")
    placeholder_cvar = structured_c.CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(
        placeholder_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        statements=structured_c.CStatements([stmt], codegen=codegen),
        body=None,
        unified_local_vars={},
        variables_in_use={
            placeholder_var: placeholder_cvar,
        },
        sort_local_vars=lambda: None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_stack_local_declaration_candidates = {
        id(placeholder_var): (placeholder_var, placeholder_cvar),
    }

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -6
    assert lhs.variable.base == "bp"
    assert lhs.variable.size == 1
    assert lhs.variable in codegen.cfunc.variables_in_use
    assert lhs.variable in codegen.cfunc.unified_local_vars
    assert placeholder_var not in codegen.cfunc.variables_in_use


def test_binary_specific_annotations_apply_generic_metadata(monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_apply(project, **kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(decompile, "apply_x86_16_metadata_annotations", fake_apply)
    project = SimpleNamespace()
    lst_metadata = SimpleNamespace()
    cod_metadata = SimpleNamespace()
    synthetic_globals = {0x10: ("foo", 1)}

    changed = decompile._apply_binary_specific_annotations(
        project,
        Path("sample.cod"),
        lst_metadata,
        func_addr=0x1000,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    assert changed is True
    assert calls == [
        {
            "func_addr": 0x1000,
            "cod_metadata": cod_metadata,
            "lst_metadata": lst_metadata,
            "synthetic_globals": synthetic_globals,
        }
    ]


def test_tiny_wrapper_staging_locals_are_pruned_structurally():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=None, variables_in_use={}, unified_local_vars={}),
        project=SimpleNamespace(arch=decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    source_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(4, 2, base="bp", name="path", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(0, 2, base="bp", name="s_2", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_mode = decompile.structured_c.CVariable(
        decompile.SimStackVariable(2, 2, base="bp", name="s_4", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )

    call = decompile.structured_c.CExpressionStatement(
        decompile.structured_c.CFunctionCall(
            "openFile",
            SimpleNamespace(name="openFile"),
            [staging_value, staging_mode],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = decompile.structured_c.CStatements(
        [
            decompile.structured_c.CAssignment(
                staging_value,
                decompile.structured_c.CConstant(0x1234, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                staging_mode,
                decompile.structured_c.CConstant(3, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                source_value,
                decompile.structured_c.CConstant(0x5678, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            call,
        ],
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        staging_value.variable: SimpleNamespace(),
        staging_mode.variable: SimpleNamespace(),
        source_value.variable: SimpleNamespace(),
    }

    changed = decompile._prune_tiny_wrapper_staging_locals(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(codegen.cfunc.statements.statements[0], decompile.structured_c.CAssignment)
    assert isinstance(codegen.cfunc.statements.statements[1], decompile.structured_c.CExpressionStatement)
    assert codegen.cfunc.statements.statements[1].expr.args[0].value == 0x1234
    assert codegen.cfunc.statements.statements[1].expr.args[1].value == 3
    assert staging_value.variable not in codegen.cfunc.variables_in_use
    assert staging_mode.variable not in codegen.cfunc.variables_in_use
