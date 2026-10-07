from __future__ import annotations

import sys
from pathlib import Path

from tools.dev.check_sortd_sidecar_free import (
    DEFAULT_MAXIMUM_EMPTY,
    DEFAULT_MAXIMUM_TIMEOUTS,
    DEFAULT_MINIMUM_DECOMPILED,
    EXPECTED_SORTD_FUNCTION_ADDRS,
    REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS,
    _parse_args,
    default_decompiler_command,
    default_decompiler_environment,
    evaluate_sortd_transcript,
    mz_executable_image,
)


def _passing_transcript() -> str:
    required_bodies = {
        0x102E0: "void sub_102e0(void) { switch (ax) { case 27: return; } }",
        0x10498: "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
        0x10E70: (
            "void sub_10e70(unsigned short arg, short arg_6) "
            "{ if (arg_6 < 75) { arg_6 = 75; } return; }"
        ),
    }
    function_rows = "\n".join(
        f"/* == function {addr:#x} sub_{addr:x} == */\n"
        f"/* failure family: status={'ok' if addr in REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS else 'validation_failed'} "
        "stage=not_set sidecar=not_attempted nonopt=not_attempted fallback=file_sweep "
        f"validation={'passed' if addr in REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS else 'failed'} */"
        + (f"\n{required_bodies[addr]}" if addr in required_bodies else "")
        for addr in EXPECTED_SORTD_FUNCTION_ADDRS
    )
    return (
        "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis. */\n"
        "/* source-region discovery evidence: raw_fact_count=20 normalized_fact_count=20 "
        "classified_fact_count=20 materialized_count=20 failure_count=0 failed_addrs=none */\n"
        "/* functions queued for decompilation: 20 */\n"
        "/* info: selected 20 function(s) for decompilation */\n"
        f"{function_rows}\n"
        "/* info: decompilation attempted for 20/20 selected function(s) */\n"
        f"/* summary: decompiled {DEFAULT_MINIMUM_DECOMPILED}/20 selected functions */\n"
    )


def test_mz_executable_image_removes_appended_debug_overlay():
    header = bytearray(32)
    header[:2] = b"MZ"
    header[2:4] = (16).to_bytes(2, "little")
    header[4:6] = (2).to_bytes(2, "little")
    data = bytes(header) + b"\0" * (528 - len(header)) + b"NB02debug"

    assert mz_executable_image(data) == data[:528]


def test_sidecar_free_ratchet_defaults_track_current_whole_file_floor():
    args = _parse_args([])

    assert DEFAULT_MINIMUM_DECOMPILED == 20
    assert DEFAULT_MAXIMUM_EMPTY == 0
    assert DEFAULT_MAXIMUM_TIMEOUTS == 0
    assert args.minimum_decompiled == DEFAULT_MINIMUM_DECOMPILED
    assert args.maximum_empty == DEFAULT_MAXIMUM_EMPTY
    assert args.maximum_timeouts == DEFAULT_MAXIMUM_TIMEOUTS


def test_sidecar_free_lane_runs_default_cli_without_forced_serial_override(monkeypatch):
    monkeypatch.setenv("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", "1")
    binary = Path("/tmp/SORTD.EXE")

    assert default_decompiler_command(binary) == (sys.executable, "decompile.py", str(binary))
    assert "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION" not in default_decompiler_environment()


def test_sidecar_free_ratchet_accepts_complete_catalog_and_current_floor():
    result = evaluate_sortd_transcript(
        _passing_transcript(),
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert result.passed
    assert result.materialized_count == 20
    assert result.attempted_count == 20
    assert result.decompiled_count == 20
    assert result.decompiled_function_addrs == REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS
    assert result.timeout_count == 0


def test_sidecar_free_ratchet_rejects_silent_function_loss():
    transcript = _passing_transcript().replace(
        f"/* == function {EXPECTED_SORTD_FUNCTION_ADDRS[-1]:#x} sub_{EXPECTED_SORTD_FUNCTION_ADDRS[-1]:x} == */",
        "/* == function 0x10f39 sub_10f39 == */",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "emitted function address set differs from the executable-only oracle" in result.violations


def test_sidecar_free_ratchet_rejects_required_function_acceptance_regression() -> None:
    required_addr = REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS[0]
    transcript = _passing_transcript().replace(
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=ok",
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=validation_failed",
        1,
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert f"required decompiled function regressions: {required_addr:#x}" in result.violations


def test_sidecar_free_ratchet_uses_successful_retry_as_terminal_acceptance() -> None:
    required_addr = REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS[-1]
    transcript = _passing_transcript().replace(
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=ok",
        f"/* == function {required_addr:#x} sub_{required_addr:x} == */\n"
        "/* failure family: status=validation_failed",
        1,
    )
    transcript = transcript.replace(
        f"/* summary: decompiled {DEFAULT_MINIMUM_DECOMPILED}/20 selected functions */",
        f"/* info: function {required_addr:#x} sub_{required_addr:x} "
        "attempt=decompiled validation=passed */\n"
        f"/* summary: decompiled {DEFAULT_MINIMUM_DECOMPILED}/20 selected functions */",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert result.passed
    assert result.validation_failed_count == 0
    assert required_addr in result.decompiled_function_addrs


def test_sidecar_free_ratchet_rejects_runmenu_without_proven_escape_exit() -> None:
    transcript = _passing_transcript().replace("case 27: return;", "case 27: break;")

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "RunMenu lacks its void binary-proven ESC exit" in result.violations


def test_sidecar_free_ratchet_rejects_runmenu_scalar_return() -> None:
    transcript = _passing_transcript().replace("void sub_102e0(void)", "short sub_102e0(void)")

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "RunMenu lacks its void binary-proven ESC exit" in result.violations


def test_sidecar_free_ratchet_rejects_redundant_runmenu_loop_tail_goto() -> None:
    transcript = _passing_transcript().replace(
        "case 27: return;",
        "case 69: goto LABEL_10488; case 27: return; } LABEL_10488:;",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "RunMenu retains a redundant switch-to-loop-tail goto" in result.violations


def test_sidecar_free_ratchet_rejects_unmaterialized_positive_bp_arguments() -> None:
    transcript = _passing_transcript().replace(
        "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
        "void sub_10498(void) { unsigned short local_4; // [bp+0x4]\n return; }",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "DrawTime lacks its canonical void positive-BP signature" in result.violations


def test_sidecar_free_ratchet_rejects_drawtime_semantic_artifacts() -> None:
    cases = (
        (
            "sub_10e70(arg * 60, 75);",
            "sub_10e70(arg, 75);",
            "DrawTime lacks its binary-proven frequency and duration arguments",
        ),
        (
            "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
            "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); /* unsupported instruction */ return; }",
            "generated output retains unsupported or unknown instructions",
        ),
        (
            "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
            "void sub_10498(unsigned short arg) { unsigned short flags; sub_10e70(arg * 60, 75); return; }",
            "generated output retains raw flag-state artifacts",
        ),
        (
            "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
            "void sub_10498(unsigned short arg) { if (arg * 60) { } else { } sub_10e70(arg * 60, 75); return; }",
            "DrawTime retains an empty flag-only branch",
        ),
        (
            "void sub_10498(unsigned short arg) { sub_10e70(arg * 60, 75); return; }",
            "void sub_10498(unsigned short arg) { arg = inertia_ss << 4; sub_10e70(arg * 60, 75); return; }",
            "DrawTime retains raw SS linear-address arithmetic",
        ),
    )
    for old, new, expected in cases:
        result = evaluate_sortd_transcript(
            _passing_transcript().replace(old, new, 1),
            decompiler_returncode=2,
            minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
            maximum_empty=0,
            maximum_timeouts=0,
            maximum_tracebacks=0,
        )

        assert expected in result.violations


def test_sidecar_free_ratchet_rejects_beep_scalar_return() -> None:
    transcript = _passing_transcript().replace(
        "void sub_10e70(unsigned short arg, short arg_6)",
        "short sub_10e70(unsigned short arg, short arg_6)",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "Beep lacks its void two-argument positive-BP signature" in result.violations


def test_sidecar_free_ratchet_rejects_beep_without_duration_guard() -> None:
    transcript = _passing_transcript().replace("if (arg_6 < 75) { arg_6 = 75; } ", "")

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "Beep lacks its binary-proven minimum-duration guard" in result.violations


def test_sidecar_free_ratchet_rejects_drawtime_scalar_return() -> None:
    transcript = _passing_transcript().replace(
        "void sub_10498(unsigned short arg)",
        "short sub_10498(unsigned short arg)",
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=DEFAULT_MINIMUM_DECOMPILED,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "DrawTime lacks its canonical void positive-BP signature" in result.violations


def test_sidecar_free_ratchet_rejects_any_traceback():
    result = evaluate_sortd_transcript(
        _passing_transcript() + "\nTraceback (most recent call last):\n",
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert "traceback count 1 exceeds 0" in result.violations


def test_sidecar_free_ratchet_rejects_timeout_label_on_validation_failure():
    transcript = _passing_transcript().replace(
        "/* failure family: status=ok",
        "/* -- c (partial timeout) -- */\n/* failure family: status=validation_failed",
        1,
    )

    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=2,
        minimum_decompiled=5,
        maximum_empty=0,
        maximum_timeouts=0,
        maximum_tracebacks=0,
    )

    assert not result.passed
    assert result.timeout_count == 1
    assert "timeout signal count 1 exceeds 0" in result.violations
