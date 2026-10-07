from __future__ import annotations

from inertia.cli.recompile_check_contract import RecompileCheckOutcome, RecompileCheckResult


def _result(outcome: RecompileCheckOutcome) -> RecompileCheckResult:
    return RecompileCheckResult(
        outcome=outcome,
        target="portable-flat",
        exit_code=0 if outcome is RecompileCheckOutcome.PASSED else 127,
        compiler="gcc" if outcome is not RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE else None,
        stdout="",
        stderr="",
        command=("gcc",),
        checked_payload="int main(void) { return 0; }",
        checked_payload_hash="hash",
    )


def test_outcome_is_the_authoritative_passed_state() -> None:
    assert _result(RecompileCheckOutcome.PASSED).passed is True
    assert _result(RecompileCheckOutcome.FAILED).passed is False


def test_toolchain_unavailable_is_distinct_from_compiler_rejection() -> None:
    unavailable = _result(RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE)
    rejected = _result(RecompileCheckOutcome.FAILED)

    assert unavailable.toolchain_unavailable is True
    assert rejected.toolchain_unavailable is False
