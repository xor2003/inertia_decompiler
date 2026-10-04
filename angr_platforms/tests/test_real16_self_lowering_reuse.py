"""Layer: Tests.

Responsibility: retain independent, freshly sealed full-state evidence while
avoiding duplicate lowering of identical inputs within one comparison.
"""

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from test_real16_binary_compare import LEAF, _exe

from tools.dosunit import real16_binary_compare, ssa_provenance, straightline_ssa
from tools.dosunit.real16_binary_compare import compare_binary16


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
