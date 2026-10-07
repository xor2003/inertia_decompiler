"""Layer: Tests.

Responsibility: retain independent, freshly sealed full-state evidence while
avoiding duplicate lowering of identical inputs within one comparison.
"""

import argparse
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_real16_binary_compare import LEAF, LEAF_CHANGED, _exe

import tools.dosunit.compare.real16_binary_compare as real16_binary_compare
import tools.dosunit.reporting.ssa_provenance as ssa_provenance
import tools.dosunit.compare.straightline_ssa as straightline_ssa
from tools.dosunit.compare.real16_binary_compare import (
    add_binary16_parser,
    cmd_compare_binary16,
    compare_binary16,
)


@pytest.mark.parametrize("same_path,same_catalog,expected_calls", [
    (True, True, 1), (False, True, 2), (True, False, 2), (False, False, 2),
])
def test_reuse_only_identical_invocation_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    same_path: bool, same_catalog: bool, expected_calls: int,
) -> None:
    """Same bytes elsewhere or a changed catalog cannot reuse this lowering."""
    oracle, catalog = _exe(tmp_path, "reuse", LEAF, 6)
    candidate = oracle
    if not same_path:
        candidate = tmp_path / "other.exe"
        candidate.write_bytes(oracle.read_bytes())
    candidate_catalog = deepcopy(catalog)
    if not same_catalog:
        candidate_catalog["diagnostics"] = ["different catalog"]
    original = straightline_ssa.lower_straightline_ssa_document
    calls: list[Path] = []

    def counted(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs["exe_path"])
        return original(**kwargs)

    monkeypatch.setattr(straightline_ssa, "lower_straightline_ssa_document", counted)
    report = compare_binary16(oracle, candidate, catalog, candidate_catalog)
    assert report["status"] == "proved", report
    assert len(calls) == expected_calls
    assert report["lowering_reuse"] == {"oracle": False, "candidate": expected_calls == 1}


def test_self_documents_have_independent_nested_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Comparison receives independent mutable documents and sealed evidence."""
    executable, catalog = _exe(tmp_path, "isolated", LEAF, 6)
    original = straightline_ssa.compare_ssa_documents

    def inspected(**kwargs: Any) -> dict[str, Any]:
        oracle, candidate = kwargs["oracle"], kwargs["candidate"]
        assert oracle == candidate
        assert oracle is not candidate
        assert oracle["functions"] is not candidate["functions"]
        assert oracle["functions"][0] is not candidate["functions"][0]
        assert oracle["provenance"] is not candidate["provenance"]
        candidate["functions"][0]["assignments"].append({"test_probe": True})
        assert oracle["functions"][0]["assignments"] != candidate["functions"][0]["assignments"]
        candidate["functions"][0]["assignments"].pop()
        return original(**kwargs)

    monkeypatch.setattr(straightline_ssa, "compare_ssa_documents", inspected)
    report = compare_binary16(executable, executable, catalog, catalog)
    assert report["status"] == "proved", report


def test_reuse_keeps_each_sides_freshness_and_environment_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoiding a second lift cannot bypass independent admission checks."""
    executable, catalog = _exe(tmp_path, "checks", LEAF, 6)
    counts: dict[str, int] = {}

    def count_call(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
        def counted(*args: Any, **kwargs: Any) -> Any:
            counts[name] = counts.get(name, 0) + 1
            return original(*args, **kwargs)
        return counted

    monkeypatch.setattr(straightline_ssa, "_load_lifter_project",
                        count_call("load", straightline_ssa._load_lifter_project))
    monkeypatch.setattr(ssa_provenance, "seal_lowering",
                        count_call("seal", ssa_provenance.seal_lowering))
    monkeypatch.setattr(ssa_provenance, "checked_provenance",
                        count_call("check", ssa_provenance.checked_provenance))
    monkeypatch.setattr(real16_binary_compare, "scan_lowered_parts",
                        count_call("scan", real16_binary_compare.scan_lowered_parts))
    report = compare_binary16(executable, executable, catalog, catalog)
    assert report["status"] == "proved", report
    assert counts["load"] == counts["seal"] == counts["scan"] == 2
    # Each side is checked after solving and after retries; the two lowering
    # seals above independently guard changes during evidence construction.
    assert counts["check"] >= 4
    # Each check rereads the whole semantic source tree. The two admission
    # boundaries need four reads, with no discarded diagnostic scans in between.
    assert counts["check"] <= 4


def test_binary_drift_prevents_reuse_and_refuses_stale_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed binary identity must never re-seal an old lowering as fresh."""
    executable, catalog = _exe(tmp_path, "drift", LEAF, 6)
    original = ssa_provenance.seal_lowering
    seals = 0

    def drift(document: dict[str, Any], path: Path, identity: ssa_provenance.LoweringIdentity) -> None:
        nonlocal seals
        original(document, path, identity)
        seals += 1
        if seals == 1:
            payload = path.read_bytes()
            path.write_bytes(payload[:-2] + b"\x02" + payload[-1:])

    monkeypatch.setattr(ssa_provenance, "seal_lowering", drift)
    report = compare_binary16(executable, executable, catalog, catalog)
    assert report["status"] == "unknown", report
    assert report["lowering_reuse"]["candidate"] is False
    assert report["proof"]["verdicts"][0]["reason"] == "backend_verdict"
    assert report["proof"]["verdicts"][0]["detail"] == "stale_provenance"
    assert report["provenance"]["oracle"]["complete"] is False


@pytest.mark.parametrize("side", ["oracle", "candidate"])
@pytest.mark.parametrize("mutation", ["binary", "document"])
def test_successful_backend_cannot_admit_mutated_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str, mutation: str,
) -> None:
    """Freshness after solving rejects each side even when real Z3 found equality."""
    oracle, catalog = _exe(tmp_path, "oracle", LEAF, 6)
    candidate, candidate_catalog = _exe(tmp_path, "candidate", LEAF, 6)
    paths = {"oracle": oracle, "candidate": candidate}
    original = straightline_ssa.compare_ssa_documents

    def compare_then_mutate(**kwargs: Any) -> dict[str, Any]:
        result = original(**kwargs)
        assert any(row["status"] == "passed" for row in result["results"]), result
        if mutation == "binary":
            path = paths[side]
            contents = path.read_bytes()
            path.write_bytes(contents[:-2] + b"\x02" + contents[-1:])
        else:
            kwargs[side]["parameters"]["output_regs"] = ["bx"]
        return result

    monkeypatch.setattr(straightline_ssa, "compare_ssa_documents", compare_then_mutate)
    report = compare_binary16(oracle, candidate, catalog, candidate_catalog)
    assert report["status"] == "unknown", report
    assert report["proof"]["verdicts"][0]["detail"] == "stale_provenance"
    assert report["provenance"][side]["complete"] is False


def _evidence_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Backend summary minus wall-clock solver timing (a measurement, not evidence)."""
    return {
        key: value for key, value in report["backend"]["summary"].items()
        if key != "solver_time_ms"
    }


def _counted_lowering(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Count lower_straightline_ssa_document calls through the shared seam."""
    original = straightline_ssa.lower_straightline_ssa_document
    calls: list[Path] = []

    def counted(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs["exe_path"])
        return original(**kwargs)

    monkeypatch.setattr(straightline_ssa, "lower_straightline_ssa_document", counted)
    return calls


def test_default_reuse_lowers_identical_candidate_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eligible same-input case keeps the single lowering in default mode."""
    oracle, catalog = _exe(tmp_path, "reuse", LEAF, 6)
    calls = _counted_lowering(monkeypatch)
    report = compare_binary16(oracle, oracle, catalog, catalog)
    assert report["status"] == "proved", report
    assert len(calls) == 1
    assert report["lowering_reuse_mode"] == "enabled"
    assert report["lowering_reuse"] == {"oracle": False, "candidate": True}


def test_bypass_recomputes_identical_candidate_without_deepcopy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bypassed mode lowers the eligible candidate and never deepcopies."""
    oracle, catalog = _exe(tmp_path, "bypass", LEAF, 6)
    calls = _counted_lowering(monkeypatch)
    monkeypatch.setattr(
        real16_binary_compare, "deepcopy",
        lambda *_a, **_k: pytest.fail("deepcopy reuse selected under bypass"),
    )
    report = compare_binary16(
        oracle, oracle, catalog, catalog, reuse_identical_lowering=False,
    )
    assert report["status"] == "proved", report
    assert calls == [oracle, oracle]
    assert report["lowering_reuse_mode"] == "bypassed"
    assert report["lowering_reuse"] == {"oracle": False, "candidate": False}
    # Independent lowerings, not shared mutable state.
    assert report["lowering"]["oracle"] == report["lowering"]["candidate"]


@pytest.mark.parametrize("reuse_identical_lowering", [True, False])
def test_changed_input_lowers_both_sides_in_every_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reuse_identical_lowering: bool,
) -> None:
    """Ineligible inputs always lower both sides; the flag changes nothing."""
    oracle, oracle_catalog = _exe(tmp_path, "chg-o", LEAF, 6)
    candidate, candidate_catalog = _exe(tmp_path, "chg-c", LEAF_CHANGED, 6)
    calls = _counted_lowering(monkeypatch)
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog,
        reuse_identical_lowering=reuse_identical_lowering,
    )
    assert len(calls) == 2
    assert report["lowering_reuse"] == {"oracle": False, "candidate": False}
    assert report["lowering_reuse_mode"] == (
        "enabled" if reuse_identical_lowering else "bypassed"
    )


def test_verdict_and_dependency_parity_positive_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical binaries: enabled and bypassed runs emit equal proof evidence."""
    oracle, catalog = _exe(tmp_path, "parity", LEAF, 6)
    enabled = compare_binary16(oracle, oracle, catalog, catalog)
    monkeypatch.setattr(
        real16_binary_compare, "deepcopy",
        lambda *_a, **_k: pytest.fail("deepcopy reuse selected under bypass"),
    )
    bypassed = compare_binary16(
        oracle, oracle, catalog, catalog, reuse_identical_lowering=False,
    )
    assert enabled["status"] == bypassed["status"] == "proved"
    assert enabled["proof"] == bypassed["proof"]
    assert enabled["proof_domain"] == bypassed["proof_domain"]
    assert enabled["input_domain"] == bypassed["input_domain"]
    assert enabled["provenance"] == bypassed["provenance"]
    assert _evidence_summary(enabled) == _evidence_summary(bypassed)
    assert enabled["lowering"]["oracle"] == bypassed["lowering"]["candidate"]
    assert enabled["lowering_reuse_mode"] != bypassed["lowering_reuse_mode"]


def test_verdict_and_dependency_parity_corruption_case(tmp_path: Path) -> None:
    """Changed leaf immediate: both modes report the same counterexample."""
    oracle, oracle_catalog = _exe(tmp_path, "corr-o", LEAF, 6)
    candidate, candidate_catalog = _exe(tmp_path, "corr-c", LEAF_CHANGED, 6)
    enabled = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog,
    )
    bypassed = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog,
        reuse_identical_lowering=False,
    )
    assert enabled["status"] == bypassed["status"] == "counterexample"
    assert enabled["proof"] == bypassed["proof"]
    assert enabled["proof_domain"] == bypassed["proof_domain"]
    assert enabled["input_domain"] == bypassed["input_domain"]
    assert enabled["provenance"] == bypassed["provenance"]
    assert _evidence_summary(enabled) == _evidence_summary(bypassed)


def _parse_and_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: list[str],
) -> dict[str, Any]:
    """Route CLI args through the real parser into a stubbed owner call."""
    captured: dict[str, Any] = {}

    def fake_compare(*_a: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"status": "proved"}

    monkeypatch.setattr(real16_binary_compare, "compare_binary16", fake_compare)
    for name in ("oracle", "candidate"):
        (tmp_path / f"{name}.exe").write_bytes(b"MZ" + b"\0" * 4)
        (tmp_path / f"{name}.json").write_text("{}")
    parser = argparse.ArgumentParser(prog="z3func")
    add_binary16_parser(parser.add_subparsers())
    args = parser.parse_args([
        "compare-binary16",
        "--oracle-exe", str(tmp_path / "oracle.exe"),
        "--candidate-exe", str(tmp_path / "candidate.exe"),
        "--oracle-functions", str(tmp_path / "oracle.json"),
        "--candidate-functions", str(tmp_path / "candidate.json"),
        "--out", str(tmp_path / "out.json"),
        *extra,
    ])
    assert cmd_compare_binary16(args) == 0
    return captured


def test_cli_no_lowering_reuse_reaches_compare_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--no-lowering-reuse reaches compare_binary16 as reuse_identical_lowering."""
    captured = _parse_and_run(monkeypatch, tmp_path, ["--no-lowering-reuse"])
    assert captured["reuse_identical_lowering"] is False


def test_cli_default_preserves_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the flag the API default of enabled reuse is forwarded."""
    captured = _parse_and_run(monkeypatch, tmp_path, [])
    assert captured["reuse_identical_lowering"] is True
