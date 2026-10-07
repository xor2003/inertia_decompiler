from __future__ import annotations

import subprocess
from pathlib import Path

from tools.compiler_toolchain.generated_c_contracts import (
    BranchBodyEffectsRequirement,
    GeneratedCContract,
)
from tools.compiler_toolchain import import_ultra_quickc_fixtures as ultra_qc

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_args_generated_c_contract_accepts_indexed_independent_calls() -> None:
    contract = ultra_qc.ARGS_FIXTURE.generated_c_contract
    assert contract is not None
    selection = ultra_qc.DecompileTargetSelection(
        mode="fixture_override",
        evidence_source="test",
        targets=("sub_10058",),
        addr=0x10058,
        reason="focused generated-C contract",
    )
    stdout = """
unsigned short sub_10058(short arg, unsigned short *arg_5)
{
    unsigned short local_4;
    if (sub_10010(SEG_PTR(inertia_ds, arg_6[local_2]), 118)) {
        local_4 = 1;
    }
    sub_10010(SEG_PTR(inertia_ds, arg_6[local_2]), 104);
    sub_106d6(676, arg_6[local_2]);
}
"""

    result = ultra_qc._decompile_result_from_output(
        command=["decompile.py"],
        selection=selection,
        targets=["sub_10058"],
        returncode=0,
        stdout=stdout,
        stderr="[tail-validation] whole-tail validation clean",
        wall_seconds=1.0,
        generated_c_contract=contract,
    )

    assert result["status"] == "passed"
    assert result["generated_c_contract"]["status"] == "passed"


def test_args_generated_c_contract_refuses_raw_segment_and_push_carriers() -> None:
    contract = ultra_qc.ARGS_FIXTURE.generated_c_contract
    assert contract is not None
    selection = ultra_qc.DecompileTargetSelection(
        mode="fixture_override",
        evidence_source="test",
        targets=("sub_10058",),
        addr=0x10058,
        reason="focused generated-C contract",
    )
    stdout = """
unsigned short sub_10058(short arg, unsigned short *arg_5)
{
    local_2 = 104;
    sub_10010(SEG_U16(ds, arg_5 + (local_2 << 1)), 104);
}
"""

    result = ultra_qc._decompile_result_from_output(
        command=["decompile.py"],
        selection=selection,
        targets=["sub_10058"],
        returncode=0,
        stdout=stdout,
        stderr="[tail-validation] whole-tail validation clean",
        wall_seconds=1.0,
        generated_c_contract=contract,
    )

    assert result["status"] == "failed"
    contract_result = result["generated_c_contract"]
    assert contract_result["status"] == "failed"
    assert "local_2 = 104;" in contract_result["present_forbidden_fragments"]
    assert contract_result["missing_indexed_argument_uses"] == [
        contract.indexed_argument_uses[0].label()
    ]


def test_args_generated_c_contract_refuses_hoisted_verbose_assignment() -> None:
    """The fixture gate must reject a branch-owned assignment at function scope."""
    contract = ultra_qc.ARGS_FIXTURE.generated_c_contract
    assert contract is not None
    stdout = """
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
unsigned short sub_10010(void *a0, unsigned short a1);
int sub_106d6(unsigned short a0, unsigned short a1);
extern unsigned short inertia_ds;
int sub_10058(short arg_4, unsigned short *arg_5)
{
    unsigned short local_4;
    unsigned short local_2;
    local_4 = 1;
    if (sub_10010(SEG_PTR(inertia_ds, arg_6[local_2]), 104)) { }
    if (sub_10010(SEG_PTR(inertia_ds, arg_6[local_2]), 118)) { }
    sub_106d6(676, arg_6[local_2]);
}
"""

    result = contract.assess(stdout).to_json()

    assert result["status"] == "failed"
    assert result["parse_error"] is None
    assert result["missing_guarded_assignments"] == [
        "local_4=1 under sub_10010(...,118)"
    ]


def test_branch_body_effect_contract_accepts_co_owned_calls_and_copy() -> None:
    contract = GeneratedCContract(
        branch_body_effects=(
            BranchBodyEffectsRequirement(
                function_name="sort",
                required_calls=("swap_values", "swap_rows"),
                assignment_name="changed",
                assignment_source_name="row",
            ),
        ),
    )
    source = """
void swap_values(void);
void swap_rows(void);
void sort(void) {
    int changed;
    int row;
    if (row) {
        swap_values();
        swap_rows();
        changed = row;
    }
}
"""

    assert contract.assess(source).passed


def test_branch_body_effect_contract_rejects_hoisted_copy() -> None:
    contract = GeneratedCContract(
        branch_body_effects=(
            BranchBodyEffectsRequirement(
                function_name="sort",
                required_calls=("swap_values", "swap_rows"),
                assignment_name="changed",
                assignment_source_name="row",
            ),
        ),
    )
    source = """
void swap_values(void);
void swap_rows(void);
void sort(void) {
    int changed;
    int row;
    if (row) {
        swap_values();
        swap_rows();
    }
    changed = row;
}
"""

    result = contract.assess(source)

    assert not result.passed
    assert result.missing_branch_body_effects == (
        "sort: changed=row with swap_values,swap_rows",
    )


def test_selected_ultra_quickc_fixtures_record_borrowed_provenance() -> None:
    fixtures = ultra_qc.selected_fixtures(None)

    assert [fixture.name for fixture in fixtures] == ["hello", "add", "whsum", "args"]
    assert fixtures[0].source_rel == "PROGRAMS/hello.c"
    assert fixtures[0].memory_model == "small"
    assert fixtures[0].compiler_flags == ("/Od", "/AS")
    assert fixtures[0].expected_exit_code == 0
    assert fixtures[0].decompile_targets == ()
    assert fixtures[0].decompile_addr is None
    assert fixtures[2].name == "whsum"
    assert fixtures[2].expected_stdout_contains == ("while sum: 15",)
    whsum_contract = fixtures[2].generated_c_contract
    assert whsum_contract is not None
    assert whsum_contract.required_fragments == (
        "void sub_105e6(unsigned short a0, unsigned short a1);",
    )


def test_switch_fixture_is_explicitly_excluded_until_fast_lane_is_deterministic() -> None:
    excluded = {fixture.name: fixture for fixture in ultra_qc.EXCLUDED_FIXTURES}

    assert "switch" in excluded
    assert "deterministic" in str(excluded["switch"].exclude_reason)


def test_quickc_reference_plan_matches_fast_lane_fixture_contract() -> None:
    plan = (REPO_ROOT / "reference" / "ultradecompiler-borrow-plan.md").read_text(encoding="utf-8")
    default_names = tuple(fixture.name for fixture in ultra_qc.selected_fixtures(None))
    default_marker = "Current fast-lane default: " + ", ".join(f"`{name}`" for name in default_names[:-1])
    default_marker = f"{default_marker}, and `{default_names[-1]}`"

    assert default_marker in plan
    assert "`switch` is\ntracked as an explicit excluded fixture" in plan
    assert "deterministic under the fast-lane timeout" in plan


def test_promoted_args_fixture_has_typed_blocker_metadata() -> None:
    fixtures = ultra_qc.selected_fixtures("args")

    assert [fixture.name for fixture in fixtures] == ["args"]
    assert fixtures[0].expected_status == "required"
    assert fixtures[0].expected_blocker is None
    assert fixtures[0].expected_stdout_contains == ("total: 2",)
    assert fixtures[0].run_args == ("-v", "alpha", "beta")
    assert "args" not in {fixture.name for fixture in ultra_qc.EXCLUDED_FIXTURES}


def test_quickc_map_entry_target_selection_is_structured(tmp_path: Path) -> None:
    map_path = tmp_path / "HELLO.MAP"
    map_path.write_text("Program entry point at 0000:0032\n", encoding="ascii")

    selection = ultra_qc._select_decompile_target(
        ultra_qc.QuickCFixtureSpec("auto", "PROGRAMS/auto.c"),
        map_path,
    )

    assert selection.mode == "auto"
    assert selection.evidence_source == "map_entry_point"
    assert selection.addr == 0x10032
    assert selection.targets == ("_start",)


def test_quickc_omf_public_target_selection_prefers_main(monkeypatch, tmp_path: Path) -> None:
    obj_path = tmp_path / "ADD.OBJ"
    obj_path.write_bytes(b"omf")
    monkeypatch.setattr(
        ultra_qc,
        "_quickc_obj_public_candidates",
        lambda _obj_path: (
            {"symbol_name": "_main", "offset": 0x1A, "addr": 0x1002A},
            {"symbol_name": "_add", "offset": 0, "addr": 0x10010},
        ),
    )

    selection = ultra_qc._select_decompile_target(
        ultra_qc.QuickCFixtureSpec("add", "PROGRAMS/add.c"),
        tmp_path / "ADD.MAP",
        obj_path=obj_path,
    )

    assert selection.mode == "auto"
    assert selection.evidence_source == "omf_public"
    assert selection.addr == 0x1002A
    assert selection.targets == ("sub_1002a",)
    assert selection.symbol_name == "_main"
    assert selection.obj_path == str(obj_path)


def test_fixture_override_target_selection_is_reported(tmp_path: Path) -> None:
    selection = ultra_qc._select_decompile_target(
        ultra_qc.QuickCFixtureSpec(
            "manual",
            "PROGRAMS/manual.c",
            decompile_targets=("sub_10010",),
            decompile_addr=0x10010,
            decompile_target_override_reason="manual target",
        ),
        tmp_path / "missing.MAP",
    )

    assert selection.mode == "override"
    assert selection.evidence_source == "fixture_metadata"
    assert selection.addr == 0x10010
    assert selection.targets == ("sub_10010",)


def test_decompile_fixture_outer_timeout_includes_cli_startup_budget(monkeypatch, tmp_path: Path) -> None:
    exe_path = tmp_path / "SAMPLE.EXE"
    exe_path.write_bytes(b"MZ")
    decompile = tmp_path / "decompile.py"
    decompile.write_text("#!/usr/bin/env python3\n", encoding="ascii")
    captured: dict[str, object] = {}

    def fake_run_with_env(
        cmd: list[str],
        *,
        timeout: int = 90,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        captured["env"] = env
        return subprocess.CompletedProcess(cmd, 0, stdout="int sub_10010(void) { return 0; }\n", stderr="")

    monkeypatch.setattr(ultra_qc, "_run_with_env", fake_run_with_env)

    result = ultra_qc._decompile_fixture(
        exe_path,
        selection=ultra_qc.DecompileTargetSelection(
            mode="auto",
            evidence_source="omf_public",
            targets=("sub_10010",),
            addr=0x10010,
            reason="test target",
        ),
        decompile=decompile,
        timeout=60,
    )

    assert result["status"] == "passed"
    assert captured["cmd"] == [
        ultra_qc.sys.executable,
        "-u",
        str(decompile),
        str(exe_path),
        "--addr",
        "0x10010",
        "--max-functions",
        "1",
        "--timeout",
        "60",
        "--no-alternate-source-c",
        "--brief",
    ]
    assert captured["timeout"] == 60 + ultra_qc.DECOMPILE_PROCESS_SETUP_TIMEOUT_SECONDS
    assert captured["env"] == {
        "INERTIA_ENABLE_TAIL_VALIDATION": "1",
        "INERTIA_DISABLE_TIMING": "1",
        "PYTHONHASHSEED": "0",
    }


def test_build_ultra_quickc_fixture_records_kvikdos_compile_link_run(monkeypatch, tmp_path: Path) -> None:
    quickc_root = tmp_path / "QuickC"
    programs = quickc_root / "PROGRAMS"
    programs.mkdir(parents=True)
    (programs / "hello.c").write_text('int main(void) { puts("Hello world"); return 0; }\n', encoding="ascii")
    (quickc_root / "QCL.EXE").write_bytes(b"")
    (quickc_root / "LINK.EXE").write_bytes(b"")
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_bytes(b"")
    decompile = tmp_path / "decompile.py"
    decompile.write_text("#!/usr/bin/env python3\n", encoding="ascii")
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        out_dir = tmp_path / "out" / "hello"
        if "e:\\QCL.EXE" in cmd:
            (out_dir / "HELLO.OBJ").write_bytes(b"obj")
            return subprocess.CompletedProcess(cmd, 0, stdout="compiled\n", stderr="")
        if "e:\\LINK.EXE" in cmd:
            (out_dir / "HELLO.EXE").write_bytes(b"exe")
            (out_dir / "HELLO.MAP").write_text("Program entry point at 0000:0032\n", encoding="ascii")
            return subprocess.CompletedProcess(cmd, 0, stdout="linked\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="Hello world\n", stderr="")

    monkeypatch.setattr(ultra_qc, "_run", fake_run)
    monkeypatch.setattr(
        ultra_qc,
        "_run_with_env",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(
            cmd, 0, stdout="unsigned short sub_10010(void) { return 0; }\n", stderr=""
        ),
    )
    monkeypatch.setattr(
        ultra_qc,
        "_compiler_evidence_for_fixture",
        lambda _exe_path: {
            "status": "passed",
            "family": "Microsoft QuickC family",
            "memory_model": "small",
            "flags": ["/Od", "/AS"],
            "raw_features": {"runtime_hits": ["Microsoft Quick C 1.0"]},
            "evidence_gap": "",
        },
    )
    monkeypatch.setattr(
        ultra_qc,
        "_quickc_obj_public_candidates",
        lambda _obj_path: ({"symbol_name": "_main", "offset": 0, "addr": 0x10010},),
    )

    result = ultra_qc.build_fixture(
        ultra_qc.DEFAULT_FIXTURES[0],
        tmp_path / "out",
        kvikdos=kvikdos,
        quickc_root=quickc_root,
        decompile=decompile,
    )

    assert result["status"] == "passed"
    assert result["origin"] == "borrow/UltraDecompiler/QuickC"
    assert result["runner"] == "kvikdos"
    assert result["toolchain_root"] == str(quickc_root)
    assert result["memory_model"] == "small"
    assert result["compiler_flags"] == ["/Od", "/AS"]
    assert result["expected_exit_code"] == 0
    assert result["decompile_targets"] == []
    assert result["decompile_addr"] is None
    assert result["decompile_target_selection"]["mode"] == "auto"
    assert result["decompile_target_selection"]["evidence_source"] == "omf_public"
    assert result["decompile_target_selection"]["addr"] == "0x10010"
    assert result["decompile_target_selection"]["symbol_name"] == "_main"
    assert [stage["stage"] for stage in result["stages"]] == ["compile", "link", "run"]
    assert result["stages"][0]["stdout"] == "compiled\n"
    assert result["stages"][1]["stdout"] == "linked\n"
    assert result["stages"][2]["stdout"] == "Hello world\n"
    assert all(isinstance(stage["wall_seconds"], float) for stage in result["stages"])
    assert result["decompile"]["status"] == "passed"
    assert isinstance(result["decompile"]["wall_seconds"], float)
    assert isinstance(result["wall_seconds"], float)
    assert result["decompile"]["generated_c_present"] is True
    assert result["decompile"]["targets"] == ["sub_10010"]
    assert result["decompile"]["target_selection"]["mode"] == "auto"
    assert result["compiler_match"]["family"] == "Microsoft QuickC family"
    assert result["compiler_match"]["memory_model"] == "small"
    assert result["compiler_match"]["flags"] == ["/Od", "/AS"]
    assert result["excluded_fixtures"][0]["reason"]
    assert all(str(kvikdos) == command[0] for command in calls)
    assert all("dosbox" not in " ".join(command).lower() for command in calls)
    assert "--env=INCLUDE=e:\\INCLUDE" in result["stages"][0]["command"]
    assert "c:\\HELLO.OBJ,c:\\HELLO.EXE,c:\\HELLO.MAP,e:\\SLIBCE.LIB;" in result["stages"][1]["command"]


def test_build_ultra_quickc_fixture_skips_missing_source(tmp_path: Path) -> None:
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_bytes(b"")

    result = ultra_qc.build_fixture(
        ultra_qc.DEFAULT_FIXTURES[0],
        tmp_path / "out",
        kvikdos=kvikdos,
        quickc_root=tmp_path / "missing-quickc",
    )

    assert result["status"] == "skipped"
    assert result["skip_reason"].startswith("missing source fixture:")
    assert result["stages"] == []


def test_build_ultra_quickc_fixture_fails_when_decompile_target_disappears(monkeypatch, tmp_path: Path) -> None:
    quickc_root = tmp_path / "QuickC"
    programs = quickc_root / "PROGRAMS"
    programs.mkdir(parents=True)
    (programs / "add.c").write_text("short add(short a, short b) { return a + b; }\nint main(void){return 0;}\n", encoding="ascii")
    (quickc_root / "QCL.EXE").write_bytes(b"")
    (quickc_root / "LINK.EXE").write_bytes(b"")
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_bytes(b"")
    decompile = tmp_path / "decompile.py"
    decompile.write_text("#!/usr/bin/env python3\n", encoding="ascii")

    def fake_run(cmd: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
        out_dir = tmp_path / "out" / "add"
        if "e:\\QCL.EXE" in cmd:
            (out_dir / "ADD.OBJ").write_bytes(b"obj")
            return subprocess.CompletedProcess(cmd, 0, stdout="compiled\n", stderr="")
        if "e:\\LINK.EXE" in cmd:
            (out_dir / "ADD.EXE").write_bytes(b"exe")
            return subprocess.CompletedProcess(cmd, 0, stdout="linked\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="15\n", stderr="")

    monkeypatch.setattr(ultra_qc, "_run", fake_run)
    monkeypatch.setattr(
        ultra_qc,
        "_run_with_env",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(cmd, 0, stdout="int main(void) { return 0; }\n", stderr=""),
    )
    monkeypatch.setattr(
        ultra_qc,
        "_compiler_evidence_for_fixture",
        lambda _exe_path: {
            "status": "passed",
            "family": "Microsoft QuickC family",
            "memory_model": "small",
            "flags": ["/Od", "/AS"],
            "raw_features": {},
            "evidence_gap": "",
        },
    )

    result = ultra_qc.build_fixture(
        ultra_qc.QuickCFixtureSpec("add", "PROGRAMS/add.c", expected_stdout_contains=("15",), decompile_targets=("add",)),
        tmp_path / "out",
        kvikdos=kvikdos,
        quickc_root=quickc_root,
        decompile=decompile,
    )

    assert result["status"] == "failed"
    assert result["decompile"]["generated_c_present"] is False
    assert result["decompile"]["missing_targets"] == ["add"]


def test_quickc_report_summary_counts_structured_statuses() -> None:
    summary = ultra_qc.summarize_results(
        [
            {
                "status": "passed",
                "expected_status": "required",
                "name": "fast",
                "wall_seconds": 1.25,
                "decompile_target_selection": {"mode": "auto"},
                "decompile": {
                    "status": "passed",
                    "generated_c_present": True,
                    "validation_status": "passed",
                    "wall_seconds": 1.0,
                },
                "compiler_match": {"status": "passed"},
            },
            {
                "status": "failed",
                "expected_status": "xfail",
                "name": "slow",
                "wall_seconds": 3.5,
                "decompile_target_selection": {"mode": "override"},
                "decompile": {
                    "status": "failed",
                    "generated_c_present": False,
                    "validation_status": "unavailable",
                    "wall_seconds": 2.25,
                },
                "compiler_match": {"status": "gap"},
            },
        ]
    )

    assert summary["selected_fixture_count"] == 2
    assert summary["passed_fixture_count"] == 1
    assert summary["xfail_fixture_count"] == 1
    assert summary["decompile_passed_count"] == 1
    assert summary["generated_c_missing_count"] == 1
    assert summary["validation_passed_count"] == 1
    assert summary["validation_unavailable_count"] == 1
    assert summary["compiler_evidence_gap_count"] == 1
    assert summary["target_selection_modes"] == {"auto": 1, "override": 1}
    assert summary["timed_fixture_count"] == 2
    assert summary["wall_seconds_total"] == 4.75
    assert summary["decompile_wall_seconds_total"] == 3.25
    assert summary["slowest_fixtures"][0]["name"] == "slow"
    assert summary["slowest_fixtures"][0]["decompile_wall_seconds"] == 2.25


def test_result_matches_expected_status_accepts_blocked_xfail_failure() -> None:
    result = {
        "status": "failed",
        "expected_status": "xfail",
        "expected_blocker": "known decompile blocker",
    }

    assert ultra_qc._result_matches_expected_status(result) is True


def test_result_matches_expected_status_rejects_xfail_without_blocker() -> None:
    result = {
        "status": "failed",
        "expected_status": "xfail",
        "expected_blocker": "",
    }

    assert ultra_qc._result_matches_expected_status(result) is False


def test_result_matches_expected_status_rejects_stale_xfail_pass() -> None:
    result = {
        "status": "passed",
        "expected_status": "xfail",
        "expected_blocker": "known decompile blocker",
    }

    assert ultra_qc._result_matches_expected_status(result) is False


def test_compiler_evidence_uses_structured_runtime_marker(tmp_path: Path) -> None:
    exe = tmp_path / "QC.EXE"
    exe.write_bytes(b"MZ\x00\x00MS Run-Time Library - Copyright (c) 1987, Microsoft Corp\x1e")

    evidence = ultra_qc._compiler_evidence_for_fixture(exe)

    assert evidence["status"] == "passed"
    assert evidence["family"] == "Microsoft QuickC family"
    assert evidence["memory_model"] == "small"
    assert evidence["flags"] == ["/Od", "/AS"]
    assert "Microsoft Quick C 1.0" in evidence["raw_features"]["runtime_hits"]
