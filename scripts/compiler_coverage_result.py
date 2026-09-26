"""Interpret existing MS C round-trip evidence without weakening its gates.

Layer: Test infrastructure.
Responsibility: classify one fresh legacy harness report into a typed outcome.
This is execution evidence, not a claim of source-feature or binary coverage.
"""

from __future__ import annotations

import json
from enum import StrEnum


class CoverageOutcome(StrEnum):
    """Terminal outcomes for a selected compiler-coverage case."""

    PASSED = "passed"
    HARNESS_FAILED = "harness_failed"
    BUILD_FAILED = "build_failed"
    ORIGINAL_RUN_FAILED = "original_run_failed"
    NOT_ATTEMPTED = "not_attempted"
    DECOMPILE_FAILED = "decompile_failed"
    VALIDATION_FAILED = "validation_failed"
    RECOMPILE_FAILED = "recompile_failed"
    BEHAVIOR_FAILED = "behavior_failed"
    TIMED_OUT = "timed_out"


def roundtrip_diagnostics(payload: object) -> dict[str, object]:
    """Keep bounded failure evidence so debugging need not dump legacy profiles."""
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        return {"report_error": "Expected exactly one case report"}
    row = payload[0]
    fields = ("build_ok", "run_ok", "decompile_ok", "decompile_recompile_ok", "decompile_run_ok",
              "run_exit_code", "decompile_run_exit_code")
    result: dict[str, object] = {name: row.get(name) for name in fields}
    profile_text = row.get("decompile_profile")
    if not isinstance(profile_text, str):
        return result
    try:
        profile = json.loads(profile_text)
    except json.JSONDecodeError:
        return result
    fallback = profile.get("fallback_rebuild") if isinstance(profile, dict) else None
    if isinstance(fallback, dict):
        result["rebuilt_exit_code"] = fallback.get("run_exit_code")
        result["source_contracts_passed"] = fallback.get("source_contracts_passed")
    return result


def _validated_functions(profile_text: object) -> bool:
    """Require final clean evidence for every selected fallback function."""
    if not isinstance(profile_text, str):
        return False
    try:
        profile = json.loads(profile_text)
    except json.JSONDecodeError:
        return False
    if not isinstance(profile, dict):
        return False
    fallback = profile.get("fallback_rebuild")
    if not isinstance(fallback, dict):
        return False
    functions, attempts = fallback.get("functions"), fallback.get("function_debug")
    if not isinstance(functions, list) or not functions or not isinstance(attempts, list):
        return False
    if any(not isinstance(name, str) or not name for name in functions):
        return False
    if len(set(functions)) != len(functions):
        return False
    final = _final_function_attempts(attempts)
    return final is not None and all(_clean_function(final.get(name)) for name in functions)


def _final_function_attempts(attempts: list[object]) -> dict[str, dict[str, object]] | None:
    """Reject malformed attempts instead of silently retaining an earlier pass."""
    final: dict[str, dict[str, object]] = {}
    for attempt in attempts:
        if not isinstance(attempt, list) or len(attempt) < 4:
            return None
        name, profile = attempt[0], attempt[3]
        if not isinstance(name, str) or not name or not isinstance(profile, dict):
            return None
        final[name] = profile
    return final


def _clean_function(profile: dict[str, object] | None) -> bool:
    """Check the final typed report fields, not rendered C or diagnostic text."""
    if profile is None:
        return False
    return (
        type(profile.get("returncode")) is int and profile["returncode"] == 0
        and profile.get("tail_validation_status") in ("clean", "passed")
        and profile.get("asm_fallback") is False
        and profile.get("timeout") is False
        and profile.get("tail_validation_changed") is False
        and profile.get("tail_validation_uncollected") is False
    )


def _matching_observations(row: dict[str, object]) -> CoverageOutcome:
    """Require concrete original/recompiled exit and output observations."""
    observations = ("run_exit_code", "decompile_run_exit_code", "run_stdout", "decompile_run_stdout")
    if any(field not in row for field in observations):
        return CoverageOutcome.HARNESS_FAILED
    if type(row["run_exit_code"]) is not int or type(row["decompile_run_exit_code"]) is not int:
        return CoverageOutcome.HARNESS_FAILED
    if not isinstance(row["run_stdout"], str) or not isinstance(row["decompile_run_stdout"], str):
        return CoverageOutcome.HARNESS_FAILED
    if row["run_exit_code"] != row["decompile_run_exit_code"] or row["run_stdout"] != row["decompile_run_stdout"]:
        return CoverageOutcome.BEHAVIOR_FAILED
    return CoverageOutcome.PASSED


def _fallback_decompilation_succeeded(profile_text: object) -> bool:
    """Separate legacy aggregate failure from successful function generation."""
    if not _validated_functions(profile_text) or not isinstance(profile_text, str):
        return False
    profile = json.loads(profile_text)
    fallback = profile["fallback_rebuild"]
    return fallback.get("decompile_ok") is True and fallback.get("source_contracts_passed") is True


def _decompilation_failure(profile_text: object) -> CoverageOutcome:
    """Preserve final deadline and validation evidence without parsing stderr."""
    if not isinstance(profile_text, str):
        return CoverageOutcome.DECOMPILE_FAILED
    try:
        profile = json.loads(profile_text)
    except json.JSONDecodeError:
        return CoverageOutcome.DECOMPILE_FAILED
    fallback = profile.get("fallback_rebuild") if isinstance(profile, dict) else None
    attempts = fallback.get("function_debug") if isinstance(fallback, dict) else None
    final = _final_function_attempts(attempts) if isinstance(attempts, list) else None
    if final is not None:
        # A deadline can prevent validation from being collected. Preserve that
        # cause, but never infer it from the CLI's shared error exit codes.
        if any(function.get("timeout") is True for function in final.values()):
            return CoverageOutcome.TIMED_OUT
        for function in final.values():
            if (not _clean_function(function)
                    and function.get("acceptance_reason") == CoverageOutcome.VALIDATION_FAILED.value):
                return CoverageOutcome.VALIDATION_FAILED
    return CoverageOutcome.DECOMPILE_FAILED


def classify_roundtrip_report(payload: object, case: str, returncode: int) -> CoverageOutcome:
    """Require one matching case and complete stage evidence before acceptance."""
    if not isinstance(payload, list) or len(payload) != 1:
        return CoverageOutcome.HARNESS_FAILED
    row = payload[0]
    if not isinstance(row, dict) or row.get("name") != case:
        return CoverageOutcome.HARNESS_FAILED
    stages = (
        ("build_ok", CoverageOutcome.BUILD_FAILED),
        ("run_ok", CoverageOutcome.ORIGINAL_RUN_FAILED),
        ("decompile_ok", CoverageOutcome.DECOMPILE_FAILED),
        ("decompile_recompile_ok", CoverageOutcome.RECOMPILE_FAILED),
        ("decompile_run_ok", CoverageOutcome.BEHAVIOR_FAILED),
    )
    for field, failure in stages:
        if field == "decompile_ok" and row.get("decompile_skipped") is not False:
            return CoverageOutcome.NOT_ATTEMPTED
        value = row.get(field)
        if field == "decompile_ok" and value is False:
            value = _fallback_decompilation_succeeded(row.get("decompile_profile"))
        if type(value) is not bool:
            return CoverageOutcome.HARNESS_FAILED
        if value is False:
            return (
                _decompilation_failure(row.get("decompile_profile"))
                if failure is CoverageOutcome.DECOMPILE_FAILED else failure
            )
    if not _validated_functions(row.get("decompile_profile")):
        return CoverageOutcome.VALIDATION_FAILED
    if returncode != 0:
        return CoverageOutcome.HARNESS_FAILED
    return _matching_observations(row)
