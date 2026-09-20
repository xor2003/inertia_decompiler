from __future__ import annotations

import pytest

from inertia_decompiler.acceptance_scorecard import build_acceptance_scorecard

_DECLARATION_AND_USE = 2


def test_acceptance_scorecard_defaults_validation_to_uncollected_without_evidence() -> None:
    output = """
/* == c == */
void main(void)
{
    unsigned short flags_3;
    unsigned short ss;
    unsigned short ds;
    unsigned short vvar_20;
    if ((flags_3 & 128) == (flags_3 & 0x800)) {}
    *((unsigned short *)((ss << 4) + vvar_20 - 2)) = 0;
    *((char *)((ds << 4) + 2978)) = 1;
    sub_104d();
}
"""

    scorecard = build_acceptance_scorecard("main", output, source_text="void main() {}\n")

    assert scorecard.function_name == "main"
    assert scorecard.raw_flags_count >= 1
    assert scorecard.raw_ss_linear_count == 1
    assert scorecard.raw_ds_linear_count == 1
    assert scorecard.vvar_count == _DECLARATION_AND_USE
    assert scorecard.anonymous_sub_count == 1
    assert scorecard.recovery_mode == "decompiled"
    assert scorecard.validation_verdict == "uncollected"
    assert scorecard.source_present is True


def test_acceptance_scorecard_detects_asm_fallback_and_validation_state() -> None:
    output = """
/* attempt: fallback validation=uncollected */
/* == asm fallback == */
0x10c00: nop
"""

    scorecard = build_acceptance_scorecard("QuickSort", output)

    assert scorecard.recovery_mode == "asm_fallback"
    assert scorecard.validation_verdict == "uncollected"
    assert scorecard.source_present is False


def test_acceptance_scorecard_detects_clean_tail_validation_console_summary() -> None:
    output = """
[tail-validation] whole-tail validation clean across 1 functions
/* == asm fallback == */
0x1000: nop
"""

    scorecard = build_acceptance_scorecard("HeapSort", output)

    assert scorecard.recovery_mode == "asm_fallback"
    assert scorecard.validation_verdict == "stable"


def test_acceptance_scorecard_detects_changed_tail_validation_console_summary() -> None:
    output = """
[tail-validation] whole-tail validation failed across 1 functions
[tail-validation] severity=changed merge_gate=hold
/* == c == */
"""

    scorecard = build_acceptance_scorecard("main", output)

    assert scorecard.validation_verdict == "failed"


@pytest.mark.parametrize("prior, final, expected", [
    ("failed", "clean", "stable"),
    ("passed", "failed", "failed"),
    ("passed", "changed", "failed"),
    ("failed", "unknown", "unknown"),
    ("passed", "uncollected", "uncollected"),
])
def test_final_whole_tail_report_owns_verdict(prior: str, final: str, expected: str) -> None:
    output = (
        f"[dbg] rejected attempt validation={prior}\n"
        "[tail-validation] whole-tail validation clean across 1 functions\n"
        f"[tail-validation] whole-tail validation {final} across 1 functions\n"
        "/* == c == */\n"
    )
    assert build_acceptance_scorecard("main", output).validation_verdict == expected


@pytest.mark.parametrize("payload, expected", [
    ('{"surface": {"severity": "changed"}}', "failed"),
    ('{"surface": []}', "stable"),
    ('{"surface": {"severity": null}}', "stable"),
    ('{invalid}', "stable"),
])
def test_structured_report_precedence_and_malformed_evidence(payload: str, expected: str) -> None:
    output = (f"@@INERTIA_TAIL_VALIDATION@@ {payload}\n"
              "[tail-validation] whole-tail validation clean across 1 functions\n")
    assert build_acceptance_scorecard("main", output).validation_verdict == expected
