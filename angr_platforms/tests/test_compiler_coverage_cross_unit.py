"""Cross-unit C contracts must reject caller/callee prototype disagreement."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import batch_decompile_procs
from scripts.compiler_coverage_cross_unit import CrossUnitStatus, check_cross_unit_c


def test_cross_unit_accepts_matching_function_pointer_interface(tmp_path: Path) -> None:
    """One logical function pointer argument survives a separate-unit link."""
    callee = tmp_path / "callee.c"
    caller = tmp_path / "caller.c"
    callee.write_text("unsigned short target(unsigned short (*fn)(unsigned short), unsigned short x)"
                      " { return fn(x); }\n", encoding="utf-8")
    caller.write_text("unsigned short target(unsigned short (*fn)(unsigned short), unsigned short x);"
                      " unsigned short identity(unsigned short x) { return x; }"
                      " unsigned short use(void) { return target(identity, 3); }\n", encoding="utf-8")

    result = check_cross_unit_c((caller, callee), tmp_path / "combined.o")

    assert result.status is CrossUnitStatus.PASSED
    assert result.returncode == 0


def test_cross_unit_refuses_far_pointer_split_into_scalar_arguments(tmp_path: Path) -> None:
    """Standalone valid C is not a coherent program when the ABI shape differs."""
    callee = tmp_path / "callee.c"
    caller = tmp_path / "caller.c"
    callee.write_text("unsigned short target(unsigned short (*fn)(unsigned short), unsigned short x)"
                      " { return fn(x); }\n", encoding="utf-8")
    caller.write_text("unsigned short target(unsigned short off, unsigned short seg, unsigned short x);"
                      " unsigned short use(void) { return target(0, 0x1000, 3); }\n", encoding="utf-8")

    result = check_cross_unit_c((caller, callee), tmp_path / "combined.o")

    assert result.status is CrossUnitStatus.COMPILATION_FAILED
    assert result.returncode != 0
    assert "-Werror=lto-type-mismatch" in result.stderr


def test_cross_unit_refuses_missing_compiler(tmp_path: Path) -> None:
    """An unavailable compiler cannot be interpreted as a passing check."""
    sources = (tmp_path / "a.c", tmp_path / "b.c")
    result = check_cross_unit_c(sources, tmp_path / "combined.o", compiler="no-such-cross-unit-compiler")
    assert result.status is CrossUnitStatus.COMPILER_UNAVAILABLE
    assert result.returncode is None


def test_cross_unit_single_source_is_not_attempted(tmp_path: Path) -> None:
    """A one-unit syntax check cannot establish cross-unit ABI agreement."""
    result = check_cross_unit_c((tmp_path / "a.c",), tmp_path / "combined.o")
    assert result.status is CrossUnitStatus.NOT_ATTEMPTED


def test_batch_cross_unit_flag_rejects_incompatible_generated_functions(tmp_path: Path, monkeypatch) -> None:
    """Two individually valid jobs cannot produce a falsely successful batch."""
    sources = {
        "callee": "unsigned short target(unsigned short (*fn)(unsigned short), unsigned short x)"
                  " { return fn(x); }\n",
        "caller": "unsigned short target(unsigned short off, unsigned short seg, unsigned short x);"
                  " unsigned short use(void) { return target(0, 0x1000, 3); }\n",
    }

    def fake_run(args, proc_name):
        output = args.out_dir / f"{proc_name}.stdout.c"
        output.write_text(sources[proc_name], encoding="utf-8")
        return batch_decompile_procs.BatchProcResult(proc_name, 0, str(output), "", 0.0, [])

    monkeypatch.setattr(batch_decompile_procs, "_run_one_proc", fake_run)
    monkeypatch.setattr(batch_decompile_procs, "decompiler_cli", type("FakeCli", (), {"main": lambda self, argv: 0})())
    out_dir = tmp_path / "batch"
    result = batch_decompile_procs.main(
        ["fixture.exe", "--out-dir", str(out_dir), "--proc", "callee", "--proc", "caller", "--check-cross-unit"]
    )

    assert result == 1
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert report["cross_unit"]["status"] == CrossUnitStatus.COMPILATION_FAILED.value


def test_batch_cross_unit_flag_records_not_attempted_after_failed_job(tmp_path: Path, monkeypatch) -> None:
    """A failed function job must prevent and explain the program-level check."""
    def fake_run(args, proc_name):
        output = args.out_dir / f"{proc_name}.stdout.c"
        output.write_text("", encoding="utf-8")
        return batch_decompile_procs.BatchProcResult(proc_name, 3, str(output), "", 0.0, [])

    def unexpected_check(*args, **kwargs):
        raise AssertionError("cross-unit compilation ran after a failed function")

    monkeypatch.setattr(batch_decompile_procs, "_run_one_proc", fake_run)
    monkeypatch.setattr(batch_decompile_procs, "check_cross_unit_c", unexpected_check)
    monkeypatch.setattr(batch_decompile_procs, "decompiler_cli", type("FakeCli", (), {"main": lambda self, argv: 0})())
    out_dir = tmp_path / "batch"
    result = batch_decompile_procs.main(
        ["fixture.exe", "--out-dir", str(out_dir), "--proc", "broken", "--check-cross-unit"]
    )

    assert result == 1
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert report["cross_unit"]["status"] == CrossUnitStatus.NOT_ATTEMPTED.value
