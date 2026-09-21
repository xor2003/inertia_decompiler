import json
import os
import subprocess
import sys
from threading import Barrier, Lock

import pytest

from scripts import batch_decompile_procs
from scripts import verify_msc_example_runtime_gate as runtime_gate
from scripts.build_msc6_examples import (
    COMPARE16_HARNESS_MAIN,
    COMPARE32_HARNESS_MAIN,
    DECOMPILE_MAX_FUNCTIONS_DEFAULT,
    DEFAULT_DECOMPILE_SKIP,
    ENUM_UNION_HARNESS_MAIN,
    FALLBACK_EXAMPLE_REBUILD,
    HARNESS_SUCCESS_EXIT_CODE,
    GeneratedFunctionReturnClass,
    GeneratedFunctionSourceContract,
    GeneratedFunctionSourceContractStatus,
    _build_fallback_source,
    _build_from_function_decompiles,
    _child_trace_path,
    _decompile_and_validate,
    _decompile_function_with_options,
    _decompile_profile_text,
    _evaluate_generated_function_source_contract,
    _extract_decompiled_function_definition,
    _focused_decompile_process_timeout,
    _is_decompile_output_acceptable,
    _make_decompile_env,
    _normalize_extracted_function_arg_placeholders,
    _parse_decompile_profile,
    _prepare_decompiled_source_for_c89,
    _run,
)


def test_fallback_keeps_target_memory_access_runtime_and_initializes_segments():
    from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

    body = "void put(unsigned short off) { SEG_U16(inertia_ds, off) = 7; }"
    source = _build_fallback_source([body], "int main(void) { return 255; }")
    assert render_c_runtime_header_8616("msc-dos") in source
    assert body in source
    assert "inertia_init_segments();" in source


def test_extract_decompiled_function_definition_handles_multiline_header():
    text = """
#include <stdint.h>

/// int cmp_i16(int a, int b)
int cmp_i16(int a, int b)

{
    if (b > a)
        return -1;
    return 0;
}
"""

    body = _extract_decompiled_function_definition(text, "cmp_i16")

    assert body.startswith("int cmp_i16(int a, int b)")
    assert "return -1;" in body


def test_build_fallback_source_includes_dos_header_for_mk_fp():
    source = _build_fallback_source(["void f(void) { MK_FP(0, 0); }\n"], "int main(void) { return 255; }")

    assert "#include <dos.h>" in source.lower()
    assert "#define MK_FP(seg, off)" in source
    assert "void f(void)" in source
    prepared = _prepare_decompiled_source_for_c89(source)
    for macro in ("PTR_U16", "PTR_U32"):
        assert f"#define {macro}(ptr)" in prepared


def test_prepare_decompiled_source_for_c89_normalizes_merged_signature_arg_collisions():
    c_text = """\
unsigned short select_and_apply(unsigned short local, unsigned long *local_2)
{
    unsigned short (*local_2)(unsigned short);
    return apply_twice(local_2, local);
}
"""

    prepared = _prepare_decompiled_source_for_c89(c_text)

    assert "select_and_apply(unsigned short local, unsigned long *local_2_2)" in prepared
    assert "unsigned long *local_2)" not in prepared
    assert "unsigned short (*local_2)(unsigned short);" in prepared


def test_extract_decompiled_function_definition_accepts_msvc_public_symbol_alias():
    text = """
int sum_globals(void)
{
    return 13;
}
"""

    body = _extract_decompiled_function_definition(text, "_sum_globals")

    assert body.startswith("int sum_globals(void)")
    assert "return 13;" in body


@pytest.mark.parametrize("body,accepted", [
    ("return apply_twice(inc_one, value);", True),
    ("unsigned short ax; ax = apply_twice(inc_one, value); inertia_esi = 0; return ax;", True),
    ("unsigned short ax = apply_twice(inc_one, value); unsigned short result = ax; return result;", True),
    ("unsigned short ax = apply_twice(inc_one, value); ax = 0; return ax;", False),
    ("unsigned short ax = apply_twice(inc_one, value); return ax + 1;", False),
    ("unsigned short ax = apply_twice(inc_one, value); consume(&ax); return ax;", False),
    ("unsigned short ax = apply_twice(inc_one, value); if (which) ax = 0; return ax;", False),
    ("unsigned short ax = apply_twice(inc_one, value); *ptr = 0; return ax;", False),
    ("unsigned short ax = other(inc_one, value); return ax;", False),
])
def test_generated_function_source_contract_accepts_value_returned_call(body, accepted):
    contract = GeneratedFunctionSourceContract(
        function_name="select_and_apply",
        required_return_class=GeneratedFunctionReturnClass.VALUE,
        required_returned_call="apply_twice",
    )

    result = _evaluate_generated_function_source_contract(
        "unsigned short select_and_apply(unsigned short which, unsigned short value) {" + body + "}",
        contract,
    )

    assert result.passed is accepted
    assert result.status is (
        GeneratedFunctionSourceContractStatus.PASSED if accepted
        else GeneratedFunctionSourceContractStatus.RETURNED_CALL_MISSING
    )
    assert result.materialized_return_class is GeneratedFunctionReturnClass.VALUE
    assert result.returned_call_present is accepted


def test_generated_function_source_contract_rejects_void_accidental_runtime_return():
    contract = GeneratedFunctionSourceContract(
        function_name="select_and_apply",
        required_return_class=GeneratedFunctionReturnClass.VALUE,
        required_returned_call="apply_twice",
    )

    result = _evaluate_generated_function_source_contract(
        """
void select_and_apply(unsigned short which, unsigned short value)
{
    apply_twice(inc_one, value);
    return;
}
""",
        contract,
    )

    assert result.passed is False
    assert result.status is GeneratedFunctionSourceContractStatus.VALUE_RETURN_REQUIRED
    assert result.materialized_return_class is GeneratedFunctionReturnClass.VOID
    assert result.returned_call_present is False


def test_generated_function_source_contract_rejects_unreturned_call():
    contract = GeneratedFunctionSourceContract(
        function_name="select_and_apply",
        required_return_class=GeneratedFunctionReturnClass.VALUE,
        required_returned_call="apply_twice",
    )

    result = _evaluate_generated_function_source_contract(
        """
unsigned short select_and_apply(unsigned short which, unsigned short value)
{
    apply_twice(inc_one, value);
    return value;
}
""",
        contract,
    )

    assert result.passed is False
    assert result.status is GeneratedFunctionSourceContractStatus.RETURNED_CALL_MISSING
    assert result.materialized_return_class is GeneratedFunctionReturnClass.VALUE
    assert result.returned_call_present is False


def test_generated_function_source_contract_accepts_void_return_class() -> None:
    contract = GeneratedFunctionSourceContract(
        function_name="swap_ptrs",
        required_return_class=GeneratedFunctionReturnClass.VOID,
    )

    result = _evaluate_generated_function_source_contract(
        """
void swap_ptrs(unsigned short *left, unsigned short *right)
{
    unsigned short tmp; // recovered stack local
    tmp = *left;
    *left = *right;
    *right = tmp;
    return;
}
""",
        contract,
    )

    assert result.passed
    assert result.status is GeneratedFunctionSourceContractStatus.PASSED
    assert result.materialized_return_class is GeneratedFunctionReturnClass.VOID


def test_generated_function_source_contract_rejects_scalar_when_void_required() -> None:
    contract = GeneratedFunctionSourceContract(
        function_name="swap_ptrs",
        required_return_class=GeneratedFunctionReturnClass.VOID,
    )

    result = _evaluate_generated_function_source_contract(
        """
short swap_ptrs(unsigned short *left, unsigned short *right)
{
    unsigned short tmp;
    tmp = *left;
    *left = *right;
    *right = tmp;
    return tmp;
}
""",
        contract,
    )

    assert result.passed is False
    assert result.status is GeneratedFunctionSourceContractStatus.VOID_RETURN_REQUIRED
    assert result.materialized_return_class is GeneratedFunctionReturnClass.VALUE


def test_generated_function_source_contract_accepts_proven_global_write() -> None:
    contract = GeneratedFunctionSourceContract(
        function_name="bump_static",
        required_global_writes=("_S104_seen",),
    )

    result = _evaluate_generated_function_source_contract(
        """
short bump_static(void)
{
    _S104_seen += 2;
    return _S104_seen;
}
""",
        contract,
    )

    assert result.passed
    assert result.status is GeneratedFunctionSourceContractStatus.PASSED
    assert result.materialized_global_writes == ("_S104_seen",)
    assert result.shadowed_global_writes == ()


def test_generated_function_source_contract_rejects_local_global_shadow() -> None:
    contract = GeneratedFunctionSourceContract(
        function_name="bump_static",
        required_global_writes=("_S104_seen",),
    )

    result = _evaluate_generated_function_source_contract(
        """
short bump_static(void)
{
    unsigned short _S104_seen;
    _S104_seen += 2;
    return _S104_seen;
}
""",
        contract,
    )

    assert result.passed is False
    assert (
        result.status
        is GeneratedFunctionSourceContractStatus.GLOBAL_SHADOWED_BY_LOCAL
    )
    assert result.materialized_global_writes == ("_S104_seen",)
    assert result.shadowed_global_writes == ("_S104_seen",)


def test_generated_function_source_contract_rejects_missing_global_write() -> None:
    contract = GeneratedFunctionSourceContract(
        function_name="bump_static",
        required_global_writes=("_S104_seen",),
    )

    result = _evaluate_generated_function_source_contract(
        """
short bump_static(void)
{
    return _S104_seen;
}
""",
        contract,
    )

    assert result.passed is False
    assert result.status is GeneratedFunctionSourceContractStatus.GLOBAL_WRITE_MISSING
    assert result.materialized_global_writes == ()
    assert result.shadowed_global_writes == ()


def test_storage_classes_gate_requires_nonshadowed_global_write() -> None:
    contracts = FALLBACK_EXAMPLE_REBUILD["storage_classes"]["source_contracts"]

    assert contracts == (
        GeneratedFunctionSourceContract(
            function_name="bump_static",
            required_global_writes=("seen",),
        ),
    )


def test_compare16_fallback_harness_checks_rel_i16_calls():
    assert "rel_i16(-2, 5)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(9, 3)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(7, 7)" in COMPARE16_HARNESS_MAIN
    assert "in_window_i16(-2, 5)" not in COMPARE16_HARNESS_MAIN


def test_child_trace_path_keeps_suffix_and_sanitizes_label():
    assert _child_trace_path("trace.agent.txt", "CMP32 compare_unsigned") == "trace.agent.CMP32_compare_unsigned.txt"
    assert _child_trace_path("trace", "CMP32/attempt:1") == "trace.CMP32_attempt_1"


def test_decompile_env_derives_child_trace_file(monkeypatch, tmp_path):
    trace_path = tmp_path / "msc.trace.txt"
    monkeypatch.setenv("PATH", "/tmp/test-path")
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FILE", str(trace_path))

    env = _make_decompile_env(False, trace_label="CMP32.compare_unsigned")

    assert env["PATH"] == "/tmp/test-path"
    assert env["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"
    assert env["INERTIA_DISABLE_TIMING"] == "1"
    assert env["INERTIA_OTEL_SPAN_FILE"] == str(tmp_path / "msc.trace.CMP32.compare_unsigned.txt")


def test_acceptance_requires_successful_process_to_supersede_failed_attempt():
    stderr = """
[dbg] direct failure family: status=empty validation=failed
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert profile["validation_state"] == []
    assert profile["failed_attempt_validation_state"] == ["failed"]
    assert profile["attempt_tail_failures"] == 1
    assert profile["tail_failures"] == 0
    assert ok is False
    assert reason == "validation_failed"

    profile["returncode"] = 0
    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert ok is True
    assert reason is None


def test_acceptance_uses_final_clean_tail_validation_over_changed_attempt():
    stderr = """
WARNING | postprocess validation changed: returns differ
[tail-validation] severity=changed
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert profile["tail_validation_changed"] is False
    assert ok is True
    assert reason is None


def test_profile_text_uses_stdout_tail_summary_after_stderr_rejection():
    stderr = """
WARNING | postprocess validation changed: returns differ
[tail-validation] severity=changed
"""
    stdout = """
int f(void) { return 1; }
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(_decompile_profile_text(stdout, stderr))

    ok, reason = _is_decompile_output_acceptable(stdout, stderr, profile)

    assert profile["tail_validation_changed"] is False
    assert profile["tail_validation_status"] == "clean"
    assert ok is True
    assert reason is None


def test_acceptance_rejects_validation_failed_fallback_even_with_clean_tail_summary():
    stderr = """
/* Decompilation validation_failed: Missing source-evidenced return values in emitted C: return value(0/1) */
/* == c (non-optimized fallback) == */
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("unsigned f(void) { return y; }", stderr, profile)

    assert ok is False
    assert reason == "validation_failed"


def test_acceptance_rejects_validation_failed_fallback_attempt_when_final_tail_is_clean():
    stderr = """
[tail-validation] whole-tail validation failed across 1 functions
/* Decompilation validation_failed: Tail validation failed (structuring=changed; postprocess=stable). */
/* == c (non-optimized fallback) == */
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert ok is False
    assert reason == "validation_failed"


@pytest.mark.parametrize(
    ("validation_state", "expected_reason"),
    (
        ("changed", "validation_changed"),
        ("uncollected", "validation_uncollected"),
    ),
)
def test_acceptance_rejects_nonpassing_function_state_despite_final_clean_tail(
    validation_state,
    expected_reason,
):
    stderr = f"""
[dbg] attempt=direct validation={validation_state}
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) {{ return 1; }}", stderr, profile)

    assert ok is False
    assert reason == expected_reason


def test_enum_union_fallback_is_enabled_by_default():
    assert "enum_union" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["enum_union"]["functions"] == ("token_cost", "combine_bytes")
    assert "token_cost(TOK_TWO)" in ENUM_UNION_HARNESS_MAIN


def test_msc6_example_gate_defaults_cover_all_functions_and_success_255():
    assert HARNESS_SUCCESS_EXIT_CODE == 255
    assert DECOMPILE_MAX_FUNCTIONS_DEFAULT == 0
    assert DEFAULT_DECOMPILE_SKIP == ()


def test_compare_harnesses_use_non_accidental_success_code():
    assert "return 255;" in COMPARE16_HARNESS_MAIN
    assert "return 255;" in COMPARE32_HARNESS_MAIN


def test_scalar_types_fallback_tracks_active_non_fpu_functions():
    functions = FALLBACK_EXAMPLE_REBUILD["scalar_types_io"]["functions"]

    assert "scale_float" not in functions
    assert "blend_double" not in functions
    assert functions == (
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
    )


def test_pointer_memory_fallback_tracks_all_runtime_checked_functions():
    config = FALLBACK_EXAMPLE_REBUILD["pointer_memory"]

    assert config["functions"] == (
        "fill_bytes",
        "sum_words",
        "swap_ptrs",
        "offset_copy",
        "select_word",
    )
    harness = config["harness"]
    assert "fill_bytes(bytes, 3, 8);" in harness
    assert "sum_words(words, 4) != 100" in harness
    assert "swap_ptrs(&a, &b);" in harness
    assert "a != 9 || b != 5" in harness
    assert "*select_word(words, 2) != 14" in harness
    assert "*select_word(words, 3) = 15" in harness
    assert "return 255;" in harness
    assert config["source_contracts"] == (
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
    )


def test_medium_structs_has_function_fallback_contract():
    assert "medium_structs" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["medium_structs"]["functions"] == (
        "accumulate_pairs",
        "rotate_triplet",
        "find_first_gt",
    )
    assert "struct Pair" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["prefix"]
    assert "return 255;" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["harness"]


def test_function_pointer_fallback_source_contract_is_enforced_before_compile(monkeypatch, tmp_path):
    contract = GeneratedFunctionSourceContract(
        function_name="select_and_apply",
        required_return_class=GeneratedFunctionReturnClass.VALUE,
        required_returned_call="apply_twice",
    )

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        return (
            True,
            """
void select_and_apply(unsigned short which, unsigned short value)
{
    apply_twice(inc_one, value);
    return;
}
""",
            "",
            {"acceptance_reason": None},
            "decompile command",
            function_name,
        )

    def fail_compile(*_args, **_kwargs):
        raise AssertionError("source-contract failure must stop before compilation")

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )
    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fail_compile)
    fallback_debug: dict[str, object] = {}

    result = _build_from_function_decompiles(
        tmp_path / "FPTR.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("select_and_apply",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="FPTR1.C",
        decompile_obj_name="FPTR1.OBJ",
        decompile_exe_name="FPTR1.EXE",
        decompile_map_name="FPTR1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
        source_contracts=(contract,),
        fallback_debug=fallback_debug,
    )

    assert result[0] is False
    assert result[1] is False
    assert fallback_debug["source_contracts_passed"] is False
    source_contract_results = fallback_debug["source_contracts"]
    assert isinstance(source_contract_results, list)
    assert source_contract_results[0]["status"] == "value_return_required"


def test_function_fallback_decompile_timeout_is_structured_failure(monkeypatch, tmp_path):
    seen: dict[str, list[str]] = {}
    seen_timeout: dict[str, int] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen_timeout["timeout"] = kwargs["timeout"]
        raise subprocess.TimeoutExpired(cmd, timeout=60, output="partial stdout", stderr="partial stderr")

    monkeypatch.setattr("scripts.build_msc6_examples._run", fake_run)

    ok, stdout, stderr, profile, command, function_name = _decompile_function_with_options(
        tmp_path / "FPTR.EXE",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        function_name="select_and_apply",
    )

    assert ok is False
    assert stdout == "partial stdout"
    assert "decompile timeout" in stderr
    assert profile["timeout"] is True
    assert profile["acceptance_reason"] == "timeout"
    assert seen["cmd"][0] == sys.executable
    assert seen_timeout["timeout"] == _focused_decompile_process_timeout(60)
    assert profile["process_timeout_seconds"] == _focused_decompile_process_timeout(60)
    assert profile["analysis_timeout_seconds"] == 60
    assert profile["quality"]["function_name"] == "select_and_apply"
    assert profile["quality"]["asm_fallback_count"] == 0
    assert "select_and_apply" in command
    assert function_name == "select_and_apply"


def test_run_merges_environment_overrides(monkeypatch):
    seen: dict[str, object] = {}

    def fake_subprocess_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setenv("INERTIA_EXISTING_FLAG", "keep")
    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    result = _run(["tool"], env={"INERTIA_ENABLE_TAIL_VALIDATION": "1"})

    assert result.returncode == 0
    assert seen["cmd"] == ["tool"]
    assert seen["env"]["INERTIA_EXISTING_FLAG"] == "keep"
    assert seen["env"]["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"


def test_batch_decompile_procs_writes_per_proc_outputs_and_report(monkeypatch, tmp_path):
    calls: list[list[str]] = []

    def fake_main(argv):
        calls.append(list(argv))
        proc_name = argv[argv.index("--proc") + 1]
        print(f"int {proc_name}(void) {{ return 1; }}")
        print(f"[tail-validation] {proc_name} clean", file=sys.stderr)
        return 1 if proc_name == "bad_proc" else 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", fake_main)

    rc = batch_decompile_procs.main(
        [
            str(tmp_path / "TEST.EXE"),
            "--out-dir",
            str(tmp_path / "batch"),
            "--proc",
            "good_proc",
            "--proc",
            "bad_proc",
            "--timeout",
            "7",
        ]
    )

    assert rc == 1
    assert len(calls) == 2
    assert calls[0][calls[0].index("--proc") + 1] == "good_proc"
    assert calls[1][calls[1].index("--proc") + 1] == "bad_proc"
    assert "int good_proc(void)" in (tmp_path / "batch" / "good_proc.stdout.c").read_text(encoding="utf-8")
    assert "[tail-validation] bad_proc clean" in (tmp_path / "batch" / "bad_proc.stderr.txt").read_text(encoding="utf-8")
    report = json.loads((tmp_path / "batch" / "batch_report.json").read_text(encoding="utf-8"))
    assert report["schema"] == "inertia.batch_decompile_procs.v1"
    assert [item["proc"] for item in report["results"]] == ["good_proc", "bad_proc"]
    assert [item["returncode"] for item in report["results"]] == [0, 1]
    assert all(isinstance(item["wall_seconds"], float) for item in report["results"])


def test_batch_decompile_procs_accepts_json_job_file(monkeypatch, tmp_path):
    calls: list[list[str]] = []

    def fake_main(argv):
        calls.append(list(argv))
        print("int sub_10010(void) { return 0; }")
        return 0

    job_file = tmp_path / "jobs.json"
    job_file.write_text(
        json.dumps(
            {
                "jobs": [
                    {
                        "name": "hello",
                        "binary": str(tmp_path / "HELLO.EXE"),
                        "addr": 0x10010,
                        "max_functions": 1,
                        "timeout": 9,
                        "alternate_source_c": False,
                        "brief": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", fake_main)

    rc = batch_decompile_procs.main(["--out-dir", str(tmp_path / "batch"), "--job-file", str(job_file)])

    assert rc == 0
    assert calls == [
        [
            "--no-alternate-source-c",
            "--brief",
            "--timeout",
            "9",
            "--addr",
            "0x10010",
            "--max-functions",
            "1",
            str(tmp_path / "HELLO.EXE"),
        ]
    ]
    report = json.loads((tmp_path / "batch" / "batch_report.json").read_text(encoding="utf-8"))
    assert report["binary"] is None
    assert report["results"][0]["proc"] == "hello"
    assert "int sub_10010(void)" in (tmp_path / "batch" / "hello.stdout.c").read_text(encoding="utf-8")


def test_batch_decompile_procs_direct_in_process_sets_and_restores_env(monkeypatch, tmp_path):
    observed_values: list[str | None] = []
    monkeypatch.setenv("INERTIA_OTEL_PROFILE_IN_PROCESS", "already-set")

    def fake_main(argv):
        observed_values.append(os.environ.get("INERTIA_OTEL_PROFILE_IN_PROCESS"))
        proc_name = argv[argv.index("--proc") + 1]
        print(f"int {proc_name}(void) {{ return 0; }}")
        return 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", fake_main)

    rc = batch_decompile_procs.main(
        [
            str(tmp_path / "TEST.EXE"),
            "--out-dir",
            str(tmp_path / "batch"),
            "--direct-in-process",
            "--proc",
            "f",
        ]
    )

    assert rc == 0
    assert observed_values == ["1"]
    assert os.environ["INERTIA_OTEL_PROFILE_IN_PROCESS"] == "already-set"


def test_function_fallback_profile_includes_quality_metrics(monkeypatch, tmp_path):
    def fake_run(cmd, **_kwargs):
        stdout = "int f(void) { if (flags) return tmp_1; return ((ss << 4) + 2); }"
        stderr = "[tail-validation] whole-tail validation clean across 1 functions\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr=stderr)

    monkeypatch.setattr("scripts.build_msc6_examples._run", fake_run)

    ok, _stdout, _stderr, profile, _command, function_name = _decompile_function_with_options(
        tmp_path / "TEST.EXE",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        function_name="f",
    )

    assert ok is True
    assert function_name == "f"
    assert profile["quality"]["function_name"] == "f"
    assert profile["quality"]["tmp_condition_count"] == 1
    assert profile["quality"]["raw_flag_condition_count"] == 1
    assert profile["quality"]["raw_ss_linear_expr_count"] == 1


def test_explicit_function_fallback_failure_does_not_probe_whole_binary(monkeypatch, tmp_path):
    def fake_build_from_function_decompiles(*_args, **_kwargs):
        return False, False, None, "", "focused failure", "", "", "", "[]"

    def fail_whole_decompile(*_args, **_kwargs):
        raise AssertionError("whole-binary decompile should not run after explicit fallback failure")

    monkeypatch.setattr(
        "scripts.build_msc6_examples._build_from_function_decompiles", fake_build_from_function_decompiles
    )
    monkeypatch.setattr("scripts.build_msc6_examples._decompile", fail_whole_decompile)

    result = _decompile_and_validate(
        tmp_path / "FPTR.EXE",
        tmp_path,
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=600,
        decompile_mode="functions",
        decompile_cod_path=None,
        decompile_max_functions=0,
        expected_exit_code=255,
        decompile_safe_names=("FPTR1.C", "FPTR1.OBJ", "FPTR1.EXE", "FPTR1.MAP"),
        decompile_fallback_rebuild={"functions": ("select_and_apply",), "harness": "int main(void) { return 255; }"},
    )

    assert result[0] is False
    profile = json.loads(result[-1])
    assert profile["acceptance_reason"] == "fallback_rebuild_failed"
    assert profile["fallback_rebuild"]["attempted"] is True


def test_function_fallback_retries_transient_asm_fallback(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        calls.append(function_name)
        if len(calls) == 1:
            return False, "", "", {"acceptance_reason": "asm_fallback", "wall_seconds": 1.25}, "cmd1", function_name
        return True, "int f(void) { return 1; }", "", {"acceptance_reason": None, "wall_seconds": 2.5}, "cmd2", function_name

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )
    monkeypatch.setattr(
        "scripts.build_msc6_examples._extract_decompiled_function_definition",
        lambda _text, _name: "int f(void) { return 1; }\n",
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))
    fallback_debug: dict[str, object] = {}

    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        tmp_path / "TEST.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
        fallback_debug=fallback_debug,
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert calls == ["f", "f"]
    assert fallback_debug["function_debug"] == [
        ["f", "f", "cmd1", {"acceptance_reason": "asm_fallback", "wall_seconds": 1.25}],
        [
            "f",
            "f",
            "cmd2",
            {"acceptance_reason": None, "retry_attempt": 2, "retry_reason": "asm_fallback", "wall_seconds": 2.5},
        ],
    ]


def test_function_fallback_uses_batch_report_when_proc_returns_nonzero_with_body(monkeypatch, tmp_path):
    exe_path = tmp_path / "TEST.EXE"
    exe_path.write_bytes(b"MZ")

    def fake_run(cmd, **_kwargs):
        assert "--direct-in-process" not in cmd
        batch_dir = tmp_path / "TEST1.batch"
        batch_dir.mkdir()
        stdout_path = batch_dir / "f.stdout.c"
        stderr_path = batch_dir / "f.stderr.txt"
        stdout_path.write_text("int f(void) { return 1; }\n", encoding="utf-8")
        stderr_path.write_text("[tail-validation] whole-tail validation clean across 1 functions\n", encoding="utf-8")
        (batch_dir / "batch_report.json").write_text(
            json.dumps(
                {
                    "schema": "inertia.batch_decompile_procs.v1",
                    "binary": str(exe_path),
                    "results": [
                        {
                            "proc": "f",
                            "returncode": 4,
                            "stdout_path": str(stdout_path),
                            "stderr_path": str(stderr_path),
                            "wall_seconds": 1.5,
                            "argv": ["--proc", "f"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 1, stdout='{"failed": 1, "selected": 1}\n', stderr="")

    def fail_serial_focused_decompile(*_args, **_kwargs):
        raise AssertionError("valid batch report should avoid serial focused fallback")

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._run", fake_run)
    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fail_serial_focused_decompile,
    )
    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    fallback_debug: dict[str, object] = {}
    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        exe_path,
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
        fallback_debug=fallback_debug,
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert fallback_debug["batch_used"] is True
    function_debug = fallback_debug["function_debug"]
    assert isinstance(function_debug, list)
    assert len(function_debug) == 1
    assert function_debug[0][0:2] == ["f", "f"]
    assert str(batch_decompile_procs.REPO_ROOT / "scripts" / "batch_decompile_procs.py") in function_debug[0][2]
    profile = function_debug[0][3]
    assert profile["acceptance_reason"] == "nonzero_exit"
    assert profile["batch_attempt"] is True
    assert profile["returncode"] == 4
    assert profile["tail_validation_status"] == "clean"
    assert profile["wall_seconds"] == 1.5


def test_function_fallback_retries_transient_tail_validation_failure(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        calls.append(function_name)
        if len(calls) == 1:
            return False, "", "", {"acceptance_reason": "tail_validation_failed"}, "cmd1", function_name
        return True, "int f(void) { return 1; }", "", {"acceptance_reason": None}, "cmd2", function_name

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )
    monkeypatch.setattr(
        "scripts.build_msc6_examples._extract_decompiled_function_definition",
        lambda _text, _name: "int f(void) { return 1; }\n",
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        tmp_path / "TEST.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert calls == ["f", "f"]


def test_function_fallback_retries_missing_generated_definition(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        calls.append(function_name)
        if len(calls) == 1:
            return True, "/* no generated function here */", "", {"acceptance_reason": None}, "cmd1", function_name
        return True, "int f(void) { return 1; }", "", {"acceptance_reason": None}, "cmd2", function_name

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        tmp_path / "TEST.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert calls == ["f", "f"]


def test_function_fallback_accepts_extractable_nonzero_function_exit(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        calls.append(function_name)
        return False, "int f(void) { return 13; }", "", {"acceptance_reason": "nonzero_exit"}, "cmd1", function_name

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )
    monkeypatch.setattr(
        "scripts.build_msc6_examples._extract_decompiled_function_definition",
        lambda _text, _name: "int f(void) { return 13; }\n",
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        tmp_path / "TEST.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert calls == ["f"]


def test_extract_normalizes_undeclared_stack_arg_placeholders_to_signature_names():
    body = """int switch_fold(int x)
{
    if (!arg_4)
        return 10;
    if (arg_4 <= 2)
        return arg_4 + 20;
    return x - 5;
}
"""

    normalized = _normalize_extracted_function_arg_placeholders(body)

    assert "arg_4" not in normalized
    assert "if (!x)" in normalized
    assert "return x + 20;" in normalized


def test_extract_does_not_rewrite_declared_local_arg_placeholder():
    body = """int f(int x)
{
    int arg_4;
    arg_4 = x + 1;
    return arg_4;
}
"""

    normalized = _normalize_extracted_function_arg_placeholders(body)

    assert "int arg_4;" in normalized
    assert "return arg_4;" in normalized


def test_runtime_gate_links_generic_runtime_support(monkeypatch, tmp_path):
    seen: dict[str, object] = {}
    exe = tmp_path / "TEST.EXE"
    exe.write_bytes(b"MZ")
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\n", encoding="utf-8")
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    example = runtime_gate.ExampleSpec(
        name="test",
        exe=exe,
        output_stem="TESTRT",
        functions=(),
        harness_main="int main(void) { return 255; }",
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        seen["runtime_support"] = kwargs.get("runtime_support")
        seen["source"] = _source_path.read_text(encoding="utf-8")
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr(runtime_gate, "_compile_and_link", fake_compile_and_link)
    monkeypatch.setattr(runtime_gate, "_run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    rebuilt = runtime_gate._verify_example(
        example,
        out_dir=tmp_path / "out",
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        decompile_py=tmp_path / "decompile.py",
        expected_exit_code=255,
        timeout=60,
    )

    assert rebuilt.name == "TESTRT.EXE"
    assert seen["runtime_support"] is True
    source = seen["source"]
    assert isinstance(source, str)
    for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        declaration = f"extern inertia_gp_lane inertia_gp_{register};"
        assert declaration in source
        assert source.index(declaration) < source.index("int main(")


def test_runtime_gate_decompiles_functions_with_bounded_parallelism(monkeypatch, tmp_path):
    exe = tmp_path / "TEST.EXE"
    exe.write_bytes(b"MZ")
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\n", encoding="utf-8")
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    example = runtime_gate.ExampleSpec(
        name="parallel-test",
        exe=exe,
        output_stem="TESTRT",
        functions=(runtime_gate.FunctionSpec("first"), runtime_gate.FunctionSpec("second")),
        harness_main="int main(void) { return 255; }",
    )
    barrier = Barrier(2)
    state_lock = Lock()
    state = {"active": 0, "max_active": 0}

    def fake_decompile(spec, **_kwargs):
        with state_lock:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        barrier.wait(timeout=2.0)
        with state_lock:
            state["active"] -= 1
        return subprocess.CompletedProcess(
            args=[spec.name],
            returncode=0,
            stdout=f"int {spec.name}(void)\n{{\n    return 0;\n}}\n",
            stderr="[tail-validation] whole-tail validation clean across 1 functions\n",
        )

    def fake_compile_and_link(source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        source = source_path.read_text(encoding="utf-8")
        assert source.index("int first(void)") < source.index("int second(void)")
        return True, "", "", "", ""

    monkeypatch.delenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", raising=False)
    monkeypatch.setattr(runtime_gate, "_run_decompile", fake_decompile)
    monkeypatch.setattr(runtime_gate, "_compile_and_link", fake_compile_and_link)
    monkeypatch.setattr(runtime_gate, "_run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    runtime_gate._verify_example(
        example,
        out_dir=tmp_path / "out",
        kvikdos=kvikdos,
        msc6_root=msc6_root,
        decompile_py=tmp_path / "decompile.py",
        expected_exit_code=255,
        timeout=60,
    )

    assert state["max_active"] == 2


def test_runtime_gate_decompile_worker_count_is_bounded(monkeypatch):
    monkeypatch.delenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", raising=False)
    assert runtime_gate._runtime_decompile_workers(1) == 1
    assert runtime_gate._runtime_decompile_workers(10) == 2

    monkeypatch.setenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", "1")
    assert runtime_gate._runtime_decompile_workers(10) == 1
    monkeypatch.setenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", "99")
    assert runtime_gate._runtime_decompile_workers(10) == 2
    monkeypatch.setenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", "invalid")
    with pytest.raises(runtime_gate.RuntimeGateError, match="invalid INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS"):
        runtime_gate._runtime_decompile_workers(10)


def test_runtime_gate_worker_control_is_not_forwarded_to_decompiler(monkeypatch, tmp_path):
    captured_env: dict[str, str] = {}

    def fake_run(*_args, **kwargs):
        captured_env.update(kwargs["env"])
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", "1")
    monkeypatch.setattr(runtime_gate.subprocess, "run", fake_run)

    runtime_gate._run_decompile(
        runtime_gate.FunctionSpec("example", proc_kind="NEAR"),
        exe_path=tmp_path / "EXAMPLE.EXE",
        decompile_py=tmp_path / "decompile.py",
        timeout=60,
    )

    assert "INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS" not in captured_env
