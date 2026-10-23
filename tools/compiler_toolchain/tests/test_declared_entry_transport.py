"""Full coverage sweeps must consume explicit, stable DOS entry evidence."""

import argparse
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from tools.compiler_toolchain import build_msc6_examples as harness
from tools.compiler_toolchain import compiler_coverage_runner as runner
from tools.compiler_toolchain import compiler_coverage_suite as suite
from tools.compiler_toolchain.compiler_coverage_result import CoverageOutcome


def test_full_sweep_forwards_declaration_without_changing_recovery_policy(tmp_path):
    """The authoritative CLI authenticates the same declaration for every worker."""
    declaration = tmp_path / "entry.json"
    command = harness._decompile_base_cmd(
        Path("decompile.py"), decompile_timeout=60,
        decompile_function_discovery_backend="auto", decompile_seed_engine="auto",
        decompile_rizin_timeout=8, decompile_ignore_local_sidecar_hints=True,
        decompile_pat_backend=None, decompile_signature_catalog=None,
        decompile_declared_input=declaration,
    )
    assert command[command.index("--real16-declared-input") + 1] == str(declaration)
    assert "--no-alternate-source-c" in command
    assert "--ignore-local-sidecar-hints" in command
    assert "--proc" not in command
    assert command[command.index("--timeout") + 1] == "60"


@pytest.mark.parametrize("mutation", [None, "replace", "delete"])
def test_runner_records_declaration_and_rejects_changed_evidence(tmp_path, monkeypatch, mutation):
    """A child cannot obtain credit against a changed or deleted entry contract."""
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    declaration = tmp_path / "entry.json"
    declaration.write_text('{"bound": "first"}')
    monkeypatch.setattr(runner, "implementation_fingerprint", lambda root: {"stable": True})

    def execute(command, log, timeout):
        assert command[command.index("--decompile-real16-declared-input") + 1] == str(declaration)
        if mutation == "replace":
            declaration.write_text('{"bound": "changed"}')
        elif mutation == "delete":
            declaration.unlink()
        return 0, False

    monkeypatch.setattr(runner, "_execute", execute)
    monkeypatch.setattr(runner, "classify_roundtrip_report", lambda *args: CoverageOutcome.PASSED)
    result = runner.run_source_case(source, tmp_path / "case", real16_declared_input=declaration)
    report = json.loads((tmp_path / "case" / "coverage-result.json").read_text())
    assert report["inputs"]["real16_declared_input"]["sha256"]
    if mutation is None:
        assert result is CoverageOutcome.PASSED
    else:
        assert result is CoverageOutcome.HARNESS_FAILED
        assert report["error"] == "Declared entry evidence changed during execution"


def test_entry_declaration_cannot_be_applied_to_a_whole_manifest(tmp_path):
    """One binary's environment must never become a corpus-wide assumption."""
    with pytest.raises(ValueError, match="one explicit schema-2 case"):
        suite.run_suite(
            Path("examples/compiler_coverage/first16.json"), tmp_path / "run",
            real16_declared_input=tmp_path / "entry.json",
        )
    assert not (tmp_path / "run").exists()


def test_legacy_manifest_refuses_declared_entry_even_with_exact_case(tmp_path):
    """The schema-1 dispatcher cannot silently drop a binary entry contract."""
    with pytest.raises(ValueError, match="one explicit schema-2 case"):
        suite.run_suite(
            Path("examples/compiler_coverage/pilot.json"), tmp_path / "run",
            case="call_composition", real16_declared_input=tmp_path / "entry.json",
        )
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("selection", [[], ["first", "second"], ["absent"]])
def test_direct_harness_rejects_zero_or_multiple_declared_sources(tmp_path, selection):
    """Actual selected sources, rather than option count, establish uniqueness."""
    (tmp_path / "first.c").touch()
    (tmp_path / "second.c").touch()
    args = argparse.Namespace(
        only_constructs=selection, examples_dir=tmp_path,
        decompile_real16_declared_input=tmp_path / "entry.json",
    )
    with pytest.raises(ValueError, match="exactly one selected source"):
        harness._selected_example_sources(args)


def test_direct_harness_preserves_single_declared_source_and_legacy_sweep(tmp_path):
    """Single-source declarations and ordinary multi-source builds both work."""
    first = tmp_path / "first.c"
    second = tmp_path / "second.c"
    first.touch()
    second.touch()
    args = argparse.Namespace(
        only_constructs=["first"], examples_dir=tmp_path,
        decompile_real16_declared_input=tmp_path / "entry.json",
        decompile_mode="functions", skip_constructs=[],
    )
    assert harness._selected_example_sources(args) == (first,)
    args.only_constructs = []
    args.decompile_real16_declared_input = None
    assert harness._selected_example_sources(args) == (first, second)


@pytest.mark.parametrize("mode,skips", [("main", []), ("functions", ["first"])])
def test_declared_harness_requires_an_unskipped_full_sweep(tmp_path, mode, skips):
    """Declaring an entry cannot grant acceptance when recovery is skipped."""
    (tmp_path / "first.c").touch()
    args = argparse.Namespace(
        only_constructs=["first"], examples_dir=tmp_path,
        decompile_real16_declared_input=tmp_path / "entry.json",
        decompile_mode=mode, skip_constructs=skips,
    )
    with pytest.raises(ValueError, match="unskipped full function sweep"):
        harness._selected_example_sources(args)


def test_frozen_dispatch_transports_the_exact_declared_file(tmp_path, monkeypatch):
    """The source pin and compiler pin remain checked by the existing owner."""
    manifest = suite.load_manifest(Path("examples/compiler_coverage/first16.json"))
    case = manifest.cases[0]
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "_run_frozen_case", execute)
    declaration = tmp_path / "entry.json"
    suite._run_candidate(
        2, case, tmp_path / "case", timeout=600, stage_budget_seconds=120,
        profile=None, evidence_path=None, real16_declared_input=declaration,
    )
    assert execute.call_args.kwargs["real16_declared_input"] == declaration
    assert execute.call_args.kwargs["stage_budget_seconds"] == 120
