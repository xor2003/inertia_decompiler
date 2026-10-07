from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.dev.sortdemo_decompiler_status as sortdemo_decompiler_status
from tools.dev.sortdemo_decompiler_status import (
    SORTDEMO_SOURCE_CALL_CONTRACTS,
    ArgumentClass,
    CallRequirement,
    FunctionCallContract,
    parse_status_text,
)


def test_sortdemo_source_call_contract_inventory_matches_cod_proc_inventory():
    repo_root = Path(__file__).resolve().parents[2]
    proc_names = sortdemo_decompiler_status._sortdemo_proc_names(
        repo_root / "SORTDEMO.COD",
        max_functions=None,
    )

    assert set(SORTDEMO_SOURCE_CALL_CONTRACTS) == set(proc_names)
    assert len(SORTDEMO_SOURCE_CALL_CONTRACTS) == 20


def test_sortdemo_source_call_contract_accepts_complete_main_call_surface():
    result = parse_status_text(
        """
/* == function 0x1000 main == */
/* info: validation=passed */
/* == c == */
int main(void)
{
    settextrows(43);
    clearscreen(0);
    displaycursor(0);
    InitBars();
    InitMenu();
    RunMenu();
    setvideomode(65535);
    return 0;
}
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["source_contract_summary"] == {"total": 1, "passed": 1, "failed": 0}
    assert result["functions"][0]["source_contract"]["passed"] is True


def test_sortdemo_status_joins_numeric_worker_c_to_source_contract():
    result = parse_status_text(
        """
[dbg] recovery worker: start 0x10554 InitBars mode=lst recovery_timeout=240s
/* function: 0x10554 sub_10554 */
/* decompiling... */
/* == function 0x10560 InitBars == */
/* failure family: status=ok stage=not_set fallback=file_sweep validation=passed */
/* info: function 0x10560 InitBars attempt=decompiled validation=passed */
/* -- c -- */
void sub_10560(void)
{
    unsigned short vc;
    sub_11402(sub_1132c(SEG_PTR(inertia_ds, 0)));
    sub_12ac8(&vc);
    sub_11414();
    sub_10678();
}
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["source_contract_summary"] == {"total": 1, "passed": 1, "failed": 0}
    assert result["functions"][0]["name"] == "InitBars"
    assert result["functions"][0]["leakage"]["raw_segmented_access"] == 1


def test_sortdemo_status_joins_deferred_canonical_definition_to_contract():
    result = parse_status_text(
        """
/* == function 0x10f38 Sleep == */
/* info: function 0x10f38 Sleep attempt=decompiled validation=passed */
unsigned short Sleep(long wait)
{
    while (clock() < wait) {
    }
    return clock();
}
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["source_contract_summary"] == {"total": 1, "passed": 1, "failed": 0}
    assert result["functions"][0]["generated_c_marker"] == "normal"


def test_sortdemo_status_joins_definitions_deferred_after_multiple_markers() -> None:
    result = parse_status_text(
        """
/* == function 0x10560 InitBars == */
/* info: function 0x10560 InitBars attempt=decompiled validation=passed */
/* == function 0x10f38 Sleep == */
/* info: function 0x10f38 Sleep attempt=decompiled validation=passed */
void sub_10560(void)
{
    int vc;
    time(0);
    srand(1);
    getvideoconfig(&vc);
    rand();
    sub_10678();
}
unsigned short sub_10f38(long wait)
{
    while (clock() < wait) {
    }
    return clock();
}
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 2, "passed": 2}
    assert result["source_contract_summary"] == {"total": 2, "passed": 2, "failed": 0}


def test_sortdemo_status_keeps_canonical_type_prelude_with_definition():
    result = parse_status_text(
        """
/* == function 0x2000 helper == */
/* info: function 0x2000 helper attempt=decompiled validation=passed */
/* == function 0x107b8 Swaps == */
/* info: function 0x107b8 Swaps attempt=decompiled validation=passed */
/* info: decompilation attempted for 2/2 selected function(s) */
[metric] worker diagnostic that is not generated C
WARNING  | decompiler diagnostic that is not generated C
typedef struct g_08F0_entry {
    char field_0;
    char field_1;
} g_08F0_entry;
void sub_2000(void)
{
    return;
}
short Swaps(g_08F0_entry *bar1, g_08F0_entry *bar2)
{
    g_08F0_entry temporary;
    temporary = bar1[0];
    bar1[0] = bar2[0];
    bar2[0] = temporary;
    return 0;
}
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 2, "passed": 2}
    assert result["source_contract_summary"] == {"total": 1, "passed": 1, "failed": 0}


def test_sortdemo_status_ignores_deallocator_cleanup_traceback_before_final_success():
    result = parse_status_text(
        """
/* function: 0x10f38 Sleep */
Exception ignored while calling deallocator <function IO.__del__>:
Traceback (most recent call last):
  File "io.py", line 50, in __del__
AnalysisTimeout:
/* failure family: status=ok stage=not_set fallback=file_sweep validation=passed */
/* info: function 0x10f38 Sleep attempt=decompiled validation=passed */
"""
    )

    assert result["summary"] == {"total": 1, "passed": 1}


def test_sortdemo_source_call_contract_accepts_generated_integer_type_footer():
    result = parse_status_text(
        """
/* == function 0x1000 main == */
/* info: validation=passed */
/* == c == */
int main(void)
{
    settextrows(43);
    clearscreen(0);
    displaycursor(0);
    InitBars();
    InitMenu();
    RunMenu();
    setvideomode(65535);
    return 0;
}
extern uint8_t inertia_memory[];
extern uint16_t inertia_words[];
extern uint32_t inertia_dwords[];
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["source_contract_summary"] == {"total": 1, "passed": 1, "failed": 0}


def test_source_call_contract_accepts_signed_fixed_width_runtime_declaration():
    contract = FunctionCallContract(
        name="f",
        calls=(
            CallRequirement(
                name="aNldiv",
                count=1,
                argument_classes=(ArgumentClass.VALUE, ArgumentClass.VALUE),
            ),
        ),
    )

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        "int32_t aNldiv(int32_t dividend, int32_t divisor);\n"
        "void f(void) { aNldiv(900L, 30L); }",
    )

    assert result.passed is True
    assert result.parse_error is None


def test_source_call_contract_accepts_time_t_runtime_declaration_and_null():
    contract = FunctionCallContract(
        name="f",
        calls=(
            CallRequirement(
                name="time",
                count=1,
                argument_classes=(ArgumentClass.POINTER_OR_NULL,),
            ),
        ),
    )

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        "time_t time(time_t *out);\nvoid f(void) { time(0); }",
    )

    assert result.passed is True
    assert result.parse_error is None


def test_source_call_contract_reports_value_pointer_inversion_without_getattr_probing():
    contract = FunctionCallContract(
        name="f",
        calls=(
            CallRequirement(
                name="consume",
                count=1,
                argument_classes=(ArgumentClass.POINTER, ArgumentClass.VALUE),
            ),
        ),
    )

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        "void f(void) { int value; consume(17, &value); }",
    )

    assert result.passed is False
    assert result.argument_mismatches == ("consume[1]: expected=(pointer,value) actual=(value,pointer)",)


def test_insertionsort_source_contract_rejects_lost_conditional_break() -> None:
    contract = SORTDEMO_SOURCE_CALL_CONTRACTS["InsertionSort"]
    emitted_c = """
struct bar { char field_0; };
struct bar abarWork[43];
void InsertionSort(void)
{
    int iRowTmp;
    int iLength;
    DrawBar(iRowTmp);
    DrawTime(iRowTmp);
    abarWork[iRowTmp] = abarWork[iRowTmp - 1];
    DrawBar(iRowTmp);
    DrawTime(iRowTmp);
}
"""

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        emitted_c,
    )

    assert result.passed is False
    assert result.missing_control_flow == (
        "conditional-break:ops=<=:ids=abarWork,iLength,iRowTmp:arrays=abarWork",
    )


def test_insertionsort_source_contract_accepts_proven_exit_guard() -> None:
    contract = SORTDEMO_SOURCE_CALL_CONTRACTS["InsertionSort"]
    emitted_c = """
struct bar { char field_0; };
struct bar abarWork[43];
void InsertionSort(void)
{
    int iRowTmp;
    int iLength;
    if (abarWork[iRowTmp - 1].field_0 <= iLength)
        break;
    DrawBar(iRowTmp);
    DrawTime(iRowTmp);
    abarWork[iRowTmp] = abarWork[iRowTmp - 1];
    DrawBar(iRowTmp);
    DrawTime(iRowTmp);
}
"""

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        emitted_c,
    )

    assert result.passed is True
    assert result.missing_control_flow == ()


def test_insertionsort_source_contract_accepts_proven_binary_exit_guard() -> None:
    contract = SORTDEMO_SOURCE_CALL_CONTRACTS["InsertionSort"]
    emitted_c = """
unsigned short g_0B4C[1];
void InsertionSort(void)
{
    unsigned short local_4;
    unsigned short local_6;
    if (!((g_0B4C[local_4 - 1] & 255) > local_6))
        break;
    DrawBar(local_4);
    DrawTime(local_4);
    DrawBar(local_4);
    DrawTime(local_4);
}
"""

    result = sortdemo_decompiler_status._evaluate_source_contract(
        contract,
        emitted_c,
    )

    assert result.passed is True
    assert result.missing_control_flow == ()


def test_sortdemo_source_call_contract_rejects_compiler_stack_probe_leakage():
    result = parse_status_text(
        """
/* == function 0x107b8 Swaps == */
/* info: validation=passed */
/* == c == */
void Swaps(void) { chkstk(); }
""",
        check_source_contracts=True,
    )

    assert result["summary"] == {"total": 1, "source-contract-refused": 1}
    assert result["functions"][0]["source_contract"]["unexpected_calls"] == ["chkstk: count=1"]


def test_sortdemo_decompiler_status_parser_classifies_terminal_statuses():
    result = parse_status_text(
        """
/* == function 0x1000 main == */
/* info: validation=passed */
void main(void) { SwapBars(1, 2); }
/* == function 0x1010 SwapBars == */
[tail-validation] acceptance-gate detail: Final quality guard rejected emitted C (unresolved-vvar).
void SwapBars(void) { int *vvar_18; vvar_18 = &v1; }
/* == function 0x1020 ShellSort == */
/* -- asm fallback -- */
/* == function 0x1030 QuickSort == */
/* failure family: status=timeout stage=recovery:lst sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
analysis timed out after 120s
/* timeout delay: 12.00s */
SEG_U16(ds, 0x0b4c);
/* == function 0x1038 HeapSort == */
/* failure family: status=timeout stage=decompilation sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
Timed out after 120s.
/* == function 0x1040 DrawFrame == */
/* failure family: status=error stage=recovery:lst sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
/* info: function 0x1040 DrawFrame attempt=error validation=uncollected */
"""
    )

    assert result["summary"] == {
        "total": 6,
        "passed": 1,
        "quality-refused": 1,
        "fallback": 1,
        "timeout": 2,
        "error": 1,
    }
    assert result["failure_stages"] == {
        "timeout": {"recovery:lst": 1, "decompilation": 1},
        "error": {"recovery:lst": 1},
    }
    functions = {function["name"]: function for function in result["functions"]}
    assert functions["main"]["status"] == "passed"
    assert functions["SwapBars"]["status"] == "quality-refused"
    assert functions["SwapBars"]["leakage"]["unresolved_vvar"] == 2
    assert functions["ShellSort"]["status"] == "fallback"
    assert functions["QuickSort"]["status"] == "timeout"
    assert functions["QuickSort"]["timeout_seconds"] == 12.0
    assert functions["QuickSort"]["timeout_message"] == "analysis timed out after 120s"
    assert functions["QuickSort"]["leakage"]["raw_segmented_access"] == 1
    assert functions["HeapSort"]["timeout_seconds"] == 120.0
    assert functions["DrawFrame"]["status"] == "error"
    assert result["triage"]["timeout"] == [
        {
            "addr": "0x1038",
            "name": "HeapSort",
            "stage": "decompilation",
            "attempt": None,
            "validation": "failed",
            "seconds": 120.0,
            "message": "Timed out after 120s.",
        },
        {
            "addr": "0x1030",
            "name": "QuickSort",
            "stage": "recovery:lst",
            "attempt": None,
            "validation": "failed",
            "seconds": 12.0,
            "message": "analysis timed out after 120s",
        },
    ]
    assert result["triage"]["error"] == [
        {
            "addr": "0x1040",
            "name": "DrawFrame",
            "stage": "recovery:lst",
            "attempt": "error",
            "validation": "uncollected",
        }
    ]


def test_sortdemo_decompiler_status_parser_accepts_direct_proc_function_header():
    result = parse_status_text(
        """
/* function: 0x10970 HeapSort */
[dbg] direct failure family: status=ok stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=passed
"""
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["functions"][0]["addr"] == "0x10970"
    assert result["functions"][0]["name"] == "HeapSort"


def test_sortdemo_decompiler_status_parser_rejects_stage_timeout_after_validation_passed():
    result = parse_status_text(
        """
/* function: 0x107b8 Swaps */
[dbg] 0x1000 Swaps TIMEOUT stage=structuring:_conditional_continue_guard_repair_8616
[dbg] direct failure family: status=ok stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=passed
[tail-validation] whole-tail validation clean across 1 functions
"""
    )

    assert result["summary"] == {"total": 1, "timeout": 1}
    assert result["functions"][0]["failure_stage"] == "structuring:_conditional_continue_guard_repair_8616"


def test_sortdemo_decompiler_status_parser_rejects_caught_traceback_after_validation_passed():
    result = parse_status_text(
        """
/* function: 0x102e0 RunMenu */
Traceback (most recent call last):
  File "decompiler_postprocess_stage.py", line 1, in _apply_step
AttributeError: 'NoneType' object has no attribute 'with_arch'
[dbg] direct failure family: status=ok stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=passed
[tail-validation] whole-tail validation clean across 1 functions
"""
    )

    assert result["summary"] == {"total": 1, "error": 1}


def test_sortdemo_decompiler_status_parser_keeps_same_name_fallback_header_in_timeout_record():
    result = parse_status_text(
        """
/* function: 0x102e0 RunMenu */
[dbg] direct failure family: status=timeout stage=decompilation sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=failed
/* Decompilation timeout: Timed out after 30s. */
/* function: 0x102cc RunMenu */
/* == asm fallback == */
0x102cc: nop
"""
    )

    assert result["summary"] == {"total": 1, "timeout": 1}
    assert result["failure_stages"] == {"timeout": {"decompilation": 1}}
    assert result["functions"][0]["addr"] == "0x102e0"
    assert result["functions"][0]["name"] == "RunMenu"
    assert result["functions"][0]["failure_stage"] == "decompilation"
    assert result["functions"][0]["leakage"]["raw_segmented_access"] == 0


def test_sortdemo_decompiler_status_parser_merges_closed_timeout_fallback_fragment():
    result = parse_status_text(
        """
/* function: 0x10c18 ShellSort */
[dbg] direct failure family: status=validation_failed stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=failed
[tail-validation] whole-tail validation failed across 1 functions
[tail-validation] severity=changed merge_gate=hold
/* Decompilation timeout: Timed out after 60s. */
/* function: 0x10bf4 ShellSort */
[tail-validation] whole-tail validation not collected across 1 functions
"""
    )

    assert result["summary"] == {"total": 1, "tail-validation-failed": 1}
    assert result["functions"][0]["name"] == "ShellSort"
    assert result["functions"][0]["addr"] == "0x10c18"
    assert result["functions"][0]["validation_failed"] is True


def test_sortdemo_decompiler_status_parser_keeps_timeout_after_validation_passed():
    result = parse_status_text(
        """
/* function: 0x10678 ReInitBars */
[dbg] direct failure family: status=validation_failed stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=failed
[tail-validation] whole-tail validation clean across 1 functions
/* Decompilation timeout: Timed out after 60s. */
/* direct validation=failed */
/* non-optimized fallback failed: unavailable after partial timeout */
/* == c (partial timeout) == */
short ReInitBars(void) { return 0; }
"""
    )

    assert result["summary"] == {"total": 1, "timeout": 1}
    function = result["functions"][0]
    assert function["status"] == "timeout"
    assert function["validation"] == "passed"
    assert function["validation_passed"] is True
    assert function["validation_failed"] is False
    assert function["failure_status"] == "ok"
    assert function["timeout_seconds"] == 60.0


def test_sortdemo_decompiler_status_parser_keeps_validation_failure_before_retry_timeout():
    result = parse_status_text(
        """
/* function: 0x10498 DrawTime */
[dbg] direct failure family: status=ok stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=failed
[tail-validation] whole-tail validation failed across 1 functions
[dbg] non-optimized fallback unavailable for 0x10498 DrawTime: shared-project slice lean: timeout: TimeoutError: Timed out after 7s (stage=build, stop_family=timeout)
"""
    )

    assert result["summary"] == {"total": 1, "tail-validation-failed": 1}
    assert result["failure_stages"] == {"tail-validation-failed": {"not_set": 1}}
    function = result["functions"][0]
    assert function["status"] == "tail-validation-failed"
    assert function["validation"] == "failed"
    assert function["timeout_seconds"] == 7.0
    assert function["timeout_message"].startswith("[dbg] non-optimized fallback unavailable")


def test_sortdemo_decompiler_status_parser_accepts_validated_retry_after_protocol_error():
    result = parse_status_text(
        """
/* == function 0x107b8 Swaps == */
/* failure family: status=error stage=clean_process_protocol sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
[05:09:06] /* retry lane: recovered validation-passed candidate */
/* info: function 0x107b8 Swaps attempt=decompiled validation=passed */
/* -- c -- */
void Swaps(unsigned short *bar1, unsigned short *bar2) { bar1[0] = bar2[0]; }
"""
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    assert result["failure_stages"] == {}
    function = result["functions"][0]
    assert function["failure_status"] == "ok"
    assert function["failure_stage"] is None
    assert function["attempt"] == "decompiled"
    assert function["validation"] == "passed"
    assert function["validation_passed"] is True
    assert function["validation_failed"] is False


def test_sortdemo_decompiler_status_parser_refuses_passed_source_backed_leakage():
    result = parse_status_text(
        """
/* == function 0x10c18 ShellSort == */
void ShellSort(void) { unsigned short vvar_18; char mem_0BAB; }
/* info: function 0x10c18 ShellSort attempt=decompiled validation=passed */
[tail-validation] whole-tail validation clean across 1 functions
"""
    )

    assert result["summary"] == {"total": 1, "source-quality-refused": 1}
    function = result["functions"][0]
    assert function["status"] == "source-quality-refused"
    assert function["validation_passed"] is True
    assert function["leakage"]["unresolved_vvar"] == 1
    assert function["leakage"]["raw_memory_symbol"] == 1


def test_sortdemo_decompiler_status_parser_ignores_rejected_validation_diagnostic_leakage():
    result = parse_status_text(
        """
/* function: 0x10a88 PercolateDown */
WARNING  | 2026-06-26 12:37:49,784 | inertia.postprocess.decompiler_postprocess_stage | Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: returns: +expr_cycle
[dbg] direct failure family: status=ok stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=direct_addr validation=passed
[tail-validation] whole-tail validation clean across 1 functions
/* == c == */
void PercolateDown(void) { iCompares += 1; }
"""
    )

    assert result["summary"] == {"total": 1, "passed": 1}
    function = result["functions"][0]
    assert function["status"] == "passed"
    assert function["leakage"]["expr_cycle"] == 0


def test_sortdemo_decompiler_status_parser_keeps_timeout_over_unaccepted_leakage():
    result = parse_status_text(
        """
/* == function 0x10ce0 QuickSort == */
/* failure family: status=timeout stage=decompilation sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
analysis timed out after 60s
void QuickSort(void) { return SEG_U16(ds, 0x0b4c); }
"""
    )

    assert result["summary"] == {"total": 1, "timeout": 1}
    function = result["functions"][0]
    assert function["status"] == "timeout"
    assert function["leakage"]["raw_segmented_access"] == 1


def test_sortdemo_decompiler_status_parser_keeps_function_pass_before_aggregate_failure():
    result = parse_status_text(
        """
/* == function 0x12d54 QCGINIT == */
/* -- asm fallback -- */
/* info: function 0x12d54 QCGINIT attempt=empty validation=passed */
[tail-validation] whole-tail validation failed across 4 functions
"""
    )

    assert result["summary"] == {"total": 1, "fallback": 1}
    function = result["functions"][0]
    assert function["status"] == "fallback"
    assert function["validation_passed"] is True
    assert function["validation_failed"] is True


def test_sortdemo_decompiler_status_parser_ignores_runtime_header_macros_for_leakage():
    result = parse_status_text(
        """
/* function: 0x102e0 RunMenu */
#define SEG_U8(seg, off) (*(uint8_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
#define SEG_U16(seg, off) (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])
[tail-validation] whole-tail validation clean across 1 functions
/* Decompilation validation_failed: Final quality guard rejected emitted C (unresolved-vvar). */
"""
    )

    leakage = result["functions"][0]["leakage"]
    assert result["functions"][0]["status"] == "quality-refused"
    assert leakage["raw_segmented_access"] == 0
    assert leakage["unresolved_vvar"] == 1


def test_sortdemo_decompiler_status_parser_keeps_run_summary_out_of_last_function():
    result = parse_status_text(
        """
/* == function 0x1000 main == */
/* failure family: status=validation_failed stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=file_sweep validation=failed */
/* -- c (partial timeout) -- */
void main(void) { InitBars(); }
/* info: decompilation attempted for 1/1 selected function(s) */
[tail-validation] severity=changed merge_gate=hold
[tail-validation] coverage=2 missing=38 unknown=0
[tail-validation] uncollected SORTDEMO.EXE:DrawBar (NEAR): timeout
/* summary: decompiled 0/1 selected functions */
/* summary: 14 discovered function(s) timed out during decompilation */
/* summary: 1 functions fell back to asm/details */
/* summary: shown=1 decompiled=0 asm_or_detail_fallback=1 */
"""
    )

    assert result["summary"] == {"total": 1, "tail-validation-failed": 1}
    assert result["failure_stages"] == {"tail-validation-failed": {"not_set": 1}}
    assert result["functions"][0]["status"] == "tail-validation-failed"
    assert result["run_summary"] == {
        "attempted": 1,
        "tail_validation": {
            "severity": "changed",
            "merge_gate": "hold",
            "coverage": 2,
            "missing": 38,
            "unknown": 0,
        },
        "tail_validation_uncollected": ["SORTDEMO.EXE:DrawBar (NEAR): timeout"],
        "decompiled": 0,
        "selected": 1,
        "timed_out": 14,
        "asm_or_detail_fallback": 1,
        "shown": 1,
        "file_summary_decompiled": 0,
        "file_summary_fallback": 1,
    }


def test_sortdemo_decompiler_status_parser_records_status_harness_timeout_before_header():
    result = parse_status_text(
        """
/* == function 0x10a61 PercolateDown == */
/* -- asm fallback -- */
0x10b2b: ret
[00:02:04] [dbg] recovery worker: start 0x1095b HeapSort mode=lst recovery_timeout=20s
/* failure family: status=timeout stage=status_harness sidecar=not_attempted nonopt=not_attempted fallback=run_sortdemo validation=failed */
status harness timed out after 360s
"""
    )

    assert result["summary"] == {"total": 2, "fallback": 1, "timeout": 1}
    assert result["failure_stages"] == {"timeout": {"status_harness": 1}}
    assert result["functions"][0]["name"] == "PercolateDown"
    assert result["functions"][0]["status"] == "fallback"
    assert result["functions"][1]["addr"] == "0x1095b"
    assert result["functions"][1]["name"] == "HeapSort"
    assert result["functions"][1]["status"] == "timeout"
    assert result["functions"][1]["failure_stage"] == "status_harness"
    assert result["functions"][1]["timeout_seconds"] == 360.0


def test_sortdemo_decompiler_status_proc_names_follow_cod_order(tmp_path):
    cod_path = tmp_path / "SORTDEMO.COD"
    cod_path.write_text(
        """
_main PROC NEAR
_main ENDP
_InitMenu PROC NEAR
_InitMenu ENDP
_DrawFrame PROC NEAR
_DrawFrame ENDP
""",
        encoding="latin-1",
    )

    assert sortdemo_decompiler_status._sortdemo_proc_names(cod_path, max_functions=2) == ["main", "InitMenu"]


@pytest.mark.parametrize(
    ("marker", "expected_marker"),
    [
        ("/* -- c -- */", "normal"),
        ("/* == c == */", "alternate_source"),
    ],
)
def test_sortdemo_decompiler_status_extracts_both_clean_c_markers(marker, expected_marker):
    record = sortdemo_decompiler_status.FunctionStatus(
        addr="0x1000",
        name="main",
        lines=[
            "/* info: validation=passed */",
            marker,
            "int main(void) { return 0; }",
        ],
        validation_passed=True,
    )

    assert (
        sortdemo_decompiler_status._emitted_c_for_record(record)
        == "int main(void) { return 0; }"
    )
    assert record.to_json()["generated_c_marker"] == expected_marker


def test_sortdemo_decompiler_status_runner_mode_writes_transcript(monkeypatch, tmp_path, capsys):
    transcript = (
        "/* == function 0x1000 Swaps == */\n"
        "/* info: validation=passed */\n"
        "/* == c == */\n"
        "void Swaps(void) {}\n"
    )
    transcript_out = tmp_path / "sortdemo.log"

    monkeypatch.setattr(
        sortdemo_decompiler_status,
        "_run_sortdemo_decompiler",
        lambda binary, timeout, *, decompile_timeout, max_functions: (transcript, 7),
    )

    result = sortdemo_decompiler_status.main(
        [
            "--run-sortdemo",
            "--require-passed",
            "--binary",
            "SORTDEMO.EXE",
            "--run-timeout",
            "1",
            "--decompile-timeout",
            "9",
            "--max-functions",
            "3",
            "--transcript-out",
            str(transcript_out),
        ]
    )

    assert result == 1
    assert transcript_out.read_text(encoding="utf-8") == transcript
    output = json.loads(capsys.readouterr().out)
    assert output["summary"] == {"total": 1, "passed": 1}
    assert output["command"]["returncode"] == 7
    assert output["command"]["timed_out"] is False
    assert "--timeout" in output["command"]["argv"]
    assert "9" in output["command"]["argv"]
    assert "--max-functions" in output["command"]["argv"]
    assert "3" in output["command"]["argv"]
    assert "--alternate-source-c" not in output["command"]["argv"]
    assert output["command"]["mode"] == "whole-binary-authoritative"
    assert output["command"]["authoritative"] is True
    assert output["command"]["elapsed_seconds"] >= 0
    assert output["command"]["transcript_path"] == str(transcript_out)


def test_sortdemo_decompiler_status_required_gate_rejects_source_contract_refusal(tmp_path, capsys):
    transcript = tmp_path / "sortdemo.log"
    transcript.write_text(
        """
/* == function 0x1000 main == */
/* info: validation=passed */
/* == c == */
int main(void) { return 0; }
""",
        encoding="utf-8",
    )

    result = sortdemo_decompiler_status.main(
        [
            str(transcript),
            "--check-source-contracts",
            "--require-passed",
        ]
    )

    assert result == 1
    output = json.loads(capsys.readouterr().out)
    assert output["summary"] == {"total": 1, "source-contract-refused": 1}
    assert output["source_contract_summary"] == {"total": 1, "passed": 0, "failed": 1}


def test_sortdemo_decompiler_status_runner_per_function_proc_mode(monkeypatch, tmp_path, capsys):
    transcript = (
        "/* function: 0x10970 Swaps */\n"
        "/* info: validation=passed */\n"
        "/* == c == */\n"
        "void Swaps(void) {}\n"
    )
    transcript_out = tmp_path / "sortdemo_proc.log"

    monkeypatch.setattr(
        sortdemo_decompiler_status,
        "_run_sortdemo_proc_decompiler",
        lambda binary, timeout, *, decompile_timeout, max_functions: (transcript, 0),
    )

    result = sortdemo_decompiler_status.main(
        [
            "--run-sortdemo",
            "--per-function-proc",
            "--binary",
            "SORTDEMO.EXE",
            "--run-timeout",
            "1",
            "--decompile-timeout",
            "9",
            "--max-functions",
            "3",
            "--transcript-out",
            str(transcript_out),
        ]
    )

    assert result == 0
    assert transcript_out.read_text(encoding="utf-8") == transcript
    output = json.loads(capsys.readouterr().out)
    assert output["summary"] == {"total": 1, "passed": 1}
    assert output["command"]["mode"] == "per-function-proc-diagnostic"
    assert output["command"]["authoritative"] is False
    assert output["command"]["timed_out"] is False
    assert "--proc" in output["command"]["argv"]
    assert "<COD PROC>" in output["command"]["argv"]


def test_sortdemo_decompiler_status_runner_records_subprocess_timeout(monkeypatch, tmp_path, capsys):
    transcript_out = tmp_path / "nested" / "sortdemo.log"

    def fake_run_sortdemo(binary, timeout, *, decompile_timeout, max_functions):
        return "partial transcript\nstatus harness timed out after 1s\n", 124

    monkeypatch.setattr(sortdemo_decompiler_status, "_run_sortdemo_decompiler", fake_run_sortdemo)

    result = sortdemo_decompiler_status.main(
        [
            "--run-sortdemo",
            "--binary",
            "SORTDEMO.EXE",
            "--run-timeout",
            "1",
            "--transcript-out",
            str(transcript_out),
        ]
    )

    assert result == 0
    assert transcript_out.read_text(encoding="utf-8").startswith("partial transcript")
    output = json.loads(capsys.readouterr().out)
    assert output["command"]["returncode"] == 124
    assert output["command"]["timed_out"] is True
