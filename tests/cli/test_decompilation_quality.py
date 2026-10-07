from __future__ import annotations

from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

import pytest

from inertia.cli.acceptance_scorecard import (
    X86_16QualityMetrics,
    format_x86_16_quality_report_8616,
    measure_x86_16_codegen_quality_8616,
    measure_x86_16_function_quality_8616,
)
from inertia.cli.decompilation_quality import assess_decompiled_c_text, assess_final_generated_c_text
import tools.dev.benchmark_optimization_quality_guard as quality_guard
from tools.dev.benchmark_optimization_quality_guard import (
    DecompileMode,
    _disable_repo_extension_modules,
    _execution_modes_are_equivalent,
    _iter_repo_extension_modules,
)


def test_makefile_serializes_mypyc_artifact_mutators() -> None:
    makefile = (Path(__file__).parents[2] / "Makefile").read_text(encoding="utf-8")

    assert "MYPYC_ARTIFACT_LOCK ?= $(CURDIR)/.cache/locks/mypyc-artifacts.lock" in makefile
    assert makefile.count('\tmkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"') == 5
    assert (
        makefile.count(
            'flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/build_mypyc.py'
        )
        == 2
    )
    assert (
        makefile.count(
            'flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/benchmark_optimization_quality_guard.py'
        )
        == 3
    )


def test_quality_guard_scopes_and_restores_python_extensions(tmp_path) -> None:
    suffix = EXTENSION_SUFFIXES[0]
    root_extension = tmp_path / f"root{suffix}"
    package_extension = tmp_path / "inertia" / "cli" / f"package{suffix}"
    cache_extension = tmp_path / ".cache" / "mypyc" / "lib" / f"cached{suffix}"
    unrelated_library = tmp_path / "borrow" / "libcapstone.so"
    stale_neighbor = root_extension.with_name(f"{root_extension.name}.disabled")
    for path in (root_extension, package_extension, cache_extension, unrelated_library):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(path.name.encode())
    stale_neighbor.write_bytes(b"stale")

    assert _iter_repo_extension_modules(tmp_path) == (package_extension, root_extension)
    with _disable_repo_extension_modules(tmp_path):
        assert not root_extension.exists()
        assert not package_extension.exists()
        assert cache_extension.exists()
        assert unrelated_library.exists()
        assert stale_neighbor.read_bytes() == b"stale"

    assert root_extension.exists()
    assert package_extension.exists()
    assert cache_extension.exists()
    assert unrelated_library.exists()
    assert stale_neighbor.read_bytes() == b"stale"


def test_quality_guard_reuses_modes_only_without_importable_extensions(tmp_path) -> None:
    cache_extension = tmp_path / ".cache" / "mypyc" / "lib" / f"cached{EXTENSION_SUFFIXES[0]}"
    cache_extension.parent.mkdir(parents=True)
    cache_extension.write_bytes(b"cached")

    assert _execution_modes_are_equivalent(
        DecompileMode.PURE_PYTHON,
        DecompileMode.DEFAULT,
        tmp_path,
    )

    active_extension = tmp_path / "inertia" / "cli" / f"active{EXTENSION_SUFFIXES[0]}"
    active_extension.parent.mkdir(parents=True)
    active_extension.write_bytes(b"active")
    assert not _execution_modes_are_equivalent(
        DecompileMode.PURE_PYTHON,
        DecompileMode.DEFAULT,
        tmp_path,
    )
    assert _execution_modes_are_equivalent(
        DecompileMode.DEFAULT,
        DecompileMode.DEFAULT,
        tmp_path,
    )


@pytest.mark.parametrize(
    ("active_extension", "expected_modes"),
    (
        (False, (DecompileMode.DEFAULT,)),
        (True, (DecompileMode.PURE_PYTHON, DecompileMode.DEFAULT)),
    ),
)
def test_quality_guard_executes_only_distinct_import_surfaces(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    active_extension: bool,
    expected_modes: tuple[DecompileMode, ...],
) -> None:
    if active_extension:
        extension = tmp_path / "inertia" / "cli" / f"active{EXTENSION_SUFFIXES[0]}"
        extension.parent.mkdir(parents=True)
        extension.write_bytes(b"active")

    observed_modes: list[DecompileMode] = []
    metrics = measure_x86_16_codegen_quality_8616("void f(void) {}", function_name="f")
    artifact = quality_guard.FunctionArtifact(
        function_addr=0x1000,
        function_name="f",
        source_path=tmp_path / "f.c",
        quality=metrics,
    )

    def fake_run_decompile(
        *,
        mode: DecompileMode,
        request: quality_guard.DecompileRunRequest,
    ) -> quality_guard.DecompileRunResult:
        observed_modes.append(mode)
        return quality_guard.DecompileRunResult(
            mode=mode,
            command=(str(request.python_executable),),
            returncode=0,
            wall_seconds=1.0,
            validation=quality_guard.ValidationStatus.PASSED,
            artifacts=(artifact,),
        )

    monkeypatch.setattr(quality_guard, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(quality_guard, "_run_decompile", fake_run_decompile)

    assert quality_guard.main([str(tmp_path / "sample.exe")]) == 0
    assert tuple(observed_modes) == expected_modes
    output = capsys.readouterr().out
    assert ("decompiled once" in output) is (not active_extension)


def test_quality_guard_restores_python_extensions_after_exception(tmp_path) -> None:
    extension = tmp_path / f"module{EXTENSION_SUFFIXES[0]}"
    extension.write_bytes(b"extension")

    with pytest.raises(RuntimeError, match="stop"), _disable_repo_extension_modules(tmp_path):
        assert not extension.exists()
        raise RuntimeError("stop")

    assert extension.read_bytes() == b"extension"


def test_x86_16_quality_metrics_count_raw_patterns_and_score() -> None:
    metrics = measure_x86_16_codegen_quality_8616(
        "void f(void) { if (tmp_14 && flags) { x = ((ss << 4) + 2); } CmpNE(a, b); }",
        function_name="f",
        function_addr=0x1234,
        validation_uncollected=True,
    )

    assert metrics.function_name == "f"
    assert metrics.function_addr == 0x1234
    assert metrics.total_bad_patterns == 3
    assert metrics.typed_condition_count == 1
    assert metrics.quality_score == 0.2
    assert metrics.to_dict()["raw_ss_linear_expr_count"] == 1


def test_x86_16_quality_report_aggregates_metrics() -> None:
    aggregate = measure_x86_16_function_quality_8616(
        [
            measure_x86_16_codegen_quality_8616("if (tmp_1) {}", function_name="a"),
            measure_x86_16_codegen_quality_8616("CmpEQ(a, b);", function_name="b"),
        ]
    )

    assert aggregate["function_count"] == 2
    assert aggregate["total_tmp_conditions"] == 1
    assert aggregate["total_typed_conditions"] == 1

    report = format_x86_16_quality_report_8616(aggregate)
    assert "Quality Report (2 functions)" in report
    assert "tmp conditions:          1" in report


def test_x86_16_quality_compatibility_exports_reporting_owner() -> None:
    """Keep historical package imports identical to the lightweight owner."""
    from inertia.frontend.x86_16.public_api import quality as compatibility_quality

    assert compatibility_quality.X86_16QualityMetrics is X86_16QualityMetrics
    assert compatibility_quality.measure_x86_16_codegen_quality_8616 is measure_x86_16_codegen_quality_8616
    assert compatibility_quality.measure_x86_16_function_quality_8616 is measure_x86_16_function_quality_8616
    assert compatibility_quality.format_x86_16_quality_report_8616 is format_x86_16_quality_report_8616


def test_assess_decompiled_c_text_rejects_raw_ir_shaped_output() -> None:
    assessment = assess_decompiled_c_text(
        "void sub(void) {\n"
        "    STORE(addr=stack_base-2, data=(Reference vvar_4{s0|1b}), size=2, endness=Iend_LE, guard=None)\n"
        "    if (...) { Goto None }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "store-op" in assessment.markers
    assert "raw-reference" in assessment.markers
    assert "goto-none" in assessment.markers


def test_assess_decompiled_c_text_accepts_normal_c() -> None:
    assessment = assess_decompiled_c_text(
        "int rand(void)\n{\n    int value;\n    value = sub_2cc0();\n    return value;\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()


def test_assess_decompiled_c_text_rejects_stack_base_return_escape() -> None:
    assessment = assess_decompiled_c_text(
        "int rel_i16(int a, int b)\n{\n    unsigned short sp_0;\n    return sp_0;\n}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "stack-base-return-escape" in assessment.markers


def test_assess_decompiled_c_text_rejects_stack_base_address_escape() -> None:
    assessment = assess_decompiled_c_text(
        "int nested_loops(int limit)\n"
        "{\n"
        "    unsigned short stack_base;\n"
        "    return *((short *)(v2 * 16 + (unsigned int)(stack_base + -2)));\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "stack-base" in assessment.markers


def test_assess_final_generated_c_text_rejects_unresolved_temporaries() -> None:
    assessment = assess_final_generated_c_text("int SwapBars(void)\n{\n    return vvar_18;\n}\n")

    assert assessment.reject_as_decompiled is True
    assert "unresolved-vvar" in assessment.markers


def test_assess_final_generated_c_text_accepts_declared_generic_temporary() -> None:
    assessment = assess_final_generated_c_text(
        "int SwapBars(void)\n{\n    int vvar_18;\n    vvar_18 = 1;\n    return vvar_18;\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert "unresolved-vvar" not in assessment.markers


def test_assess_final_generated_c_text_rejects_raw_segmented_globals() -> None:
    assessment = assess_final_generated_c_text("void DrawBar(void)\n{\n    DrawOne(SEG_U16(ds, 0x0b4c), mem_0B4E);\n}\n")

    assert assessment.reject_as_decompiled is True
    assert "raw-ds-segmented-access" in assessment.markers
    assert "raw-memory-symbol" in assessment.markers


def test_assess_final_generated_c_text_accepts_generic_c() -> None:
    assessment = assess_final_generated_c_text(
        "void HeapSort(void)\n{\n    while (i > 1) {\n        SwapBars(i, 1);\n        i -= 1;\n    }\n}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()


def test_assess_final_generated_c_text_rejects_read_unassigned_stack_local() -> None:
    assessment = assess_final_generated_c_text(
        "void InsertionSort(void)\n"
        "{\n"
        "    unsigned short barTemp; // [bp-0x8] barTemp\n"
        "    unsigned short iLength; // [bp-0x6] iLength\n"
        "    unsigned short iRow; // [bp-0x2] iRow\n"
        "    for (iRow = 0; cRow > iRow; iRow = iRow + 1)\n"
        "    {\n"
        "        if (abarWork[iRow] <= iLength)\n"
        "            break;\n"
        "        abarWork[iRow] = barTemp;\n"
        "    }\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is True
    assert "unassigned-stack-local" in assessment.markers


def test_assess_final_generated_c_text_accepts_assigned_stack_local() -> None:
    assessment = assess_final_generated_c_text(
        "void InsertionSort(void)\n"
        "{\n"
        "    unsigned short barTemp; // [bp-0x8] barTemp\n"
        "    unsigned short iLength; // [bp-0x6] iLength\n"
        "    barTemp = abarWork[iRow];\n"
        "    iLength = barTemp;\n"
        "    if (abarWork[iRow] <= iLength)\n"
        "        abarWork[iRow] = barTemp;\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False


def test_assess_final_generated_c_text_accepts_address_taken_stack_buffer() -> None:
    assessment = assess_final_generated_c_text(
        "void DrawBar(void)\n"
        "{\n"
        "    unsigned int cSpace; // [bp-0x2e] cSpace\n"
        "    unsigned int achT; // [bp-0x2c] achT\n"
        "    cSpace = cRow - (abarWork[iRow] & 255);\n"
        "    memset(&achT, 223, abarWork[iRow] & 255);\n"
        "    memset(achT + (abarWork[iRow] & 255), 32, cSpace);\n"
        "}\n"
    )

    assert assessment.reject_as_decompiled is False
    assert assessment.markers == ()
