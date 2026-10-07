from __future__ import annotations

from inertia.cli.recompilable_cases import RecompilableSubsetCase, get_x86_16_recompilable_subset_cases
from inertia.cli.recompilable_source_evidence import load_or_build_recompilable_source_evidence


def _case_by_name(name: str) -> RecompilableSubsetCase:
    return next(case for case in get_x86_16_recompilable_subset_cases() if case.name == name)


def test_load_or_build_recompilable_source_evidence_refuses_source_text_but_reports_path() -> None:
    case = _case_by_name("loadprog_real")

    c_text, evidence_path = load_or_build_recompilable_source_evidence(case)

    assert c_text is None
    assert evidence_path is not None


def test_load_or_build_recompilable_source_evidence_reports_strlen_and_bios_paths_without_writing() -> None:
    strlen_case = _case_by_name("strlen_real")
    bios_case = _case_by_name("bios_clearkeyflags_real")

    strlen_text, strlen_path = load_or_build_recompilable_source_evidence(strlen_case)
    bios_text, bios_path = load_or_build_recompilable_source_evidence(bios_case)

    assert strlen_text is None
    assert bios_text is None
    assert strlen_path is not None
    assert bios_path is not None
