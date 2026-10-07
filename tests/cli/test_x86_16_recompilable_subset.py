from __future__ import annotations

from inertia.cli.recompilable_subset import (
    describe_x86_16_recompilable_subset,
    run_x86_16_recompilable_subset_syntax_checks,
)


def test_x86_16_recompilable_subset_description_is_stable() -> None:
    desc = describe_x86_16_recompilable_subset()

    assert [item["name"] for item in desc] == [
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    ]
    assert all("expected_kind" in item and "note" in item for item in desc)


def test_x86_16_recompilable_subset_syntax_checks_pass() -> None:
    results = run_x86_16_recompilable_subset_syntax_checks()
    results_by_name = {result["name"]: result for result in results}

    assert set(results_by_name) == {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    }
    corpus_cases = {
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    }
    for name in corpus_cases:
        result = results_by_name[name]
        assert result["used_shape_ok_evidence"] is False
        assert result["decompile_path"] == "bounded_live_decompile"
        assert result["decompile_bounded"] is True
        assert result["shape_ok"] is False
        assert "evidence" not in str(result["c_text_source"])
        assert ".codex_automation/evidence_subset" not in str(result["c_text_source_path"])
        if result["c_text_source"] != "bounded_live_decompile":
            assert result["c_text_source"] == "bounded_live_decompile_failed"
            assert result["bounded_live_decompile_outcome"] == "failed_without_source_evidence"
            assert "bounded_live_decompile_error" in result

    byteops = results_by_name["byteops_real"]
    assert byteops["c_text_source_path"] == "cod/default/BYTEOPS.COD"

    dos_load_program = results_by_name["dos_loadProgram_real"]
    if dos_load_program["c_text_source"] != "bounded_live_decompile":
        assert dos_load_program["bounded_live_decompile_outcome"] == "failed_without_source_evidence"
        assert "bounded_live_decompile_error" in dos_load_program

    loadprog = results_by_name["loadprog_real"]
    assert loadprog["c_text_source_path"] == "cod/DOSFUNC.COD"

    strlen = results_by_name["strlen_real"]
    assert strlen["c_text_source_path"] == "cod/default/STRLEN.COD"

    bios = results_by_name["bios_clearkeyflags_real"]
    assert bios["c_text_source_path"] == "cod/BIOSFUNC.COD"
    essential_cases = {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
    }
    assert all(result["shape_ok"] for result in results if result["name"] in essential_cases)
