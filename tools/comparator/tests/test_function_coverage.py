"""Original coverage cannot be inflated by selection, aliases or conditional proofs."""

import pytest

from tools.comparator.function_coverage import original_function_coverage

pytestmark = pytest.mark.ssa_z3


def row(name: str, status: str) -> dict:
    return {"function": {"name": name}, "status": status}


def test_original_denominator_keeps_named_and_missing_functions() -> None:
    report = original_function_coverage(["sub_100", "start", "HeapAlloc"], [row("sub_100", "passed")])
    assert report["original_functions"] == 3
    assert report["proved_percent"] == pytest.approx(100 / 3)
    assert report["unselected_or_missing"] == ["HeapAlloc", "start"]
    assert not report["target_met"]


def test_conditional_and_non_original_results_do_not_earn_proof_coverage() -> None:
    names = [f"f{i}" for i in range(10)]
    rows = [row(name, "passed") for name in names[:8]]
    rows += [row("f8", "conditional"), row("f9", "refused"), row("extra", "passed")]
    report = original_function_coverage(names, rows)
    assert report["proved_percent"] == 80
    assert report["conditional_percent"] == 10
    assert report["non_original_results"] == ["extra"]
    assert not report["target_met"]
    rows[8] = row("f8", "passed")
    assert original_function_coverage(names, rows)["target_met"]


def test_duplicate_results_cannot_earn_coverage() -> None:
    report = original_function_coverage(["f"], [row("f", "passed"), row("f", "passed")])
    assert report["duplicate_results"] == ["f"]
    assert report["passed"] == 0
    assert not report["target_met"]


def test_empty_manifest_does_not_meet_target() -> None:
    assert not original_function_coverage([], [])["target_met"]


def test_user_target_is_strictly_more_than_eighty_percent() -> None:
    names = [f"f{i}" for i in range(100)]
    rows = [row(name, "passed") for name in names[:80]]
    assert not original_function_coverage(names, rows)["target_met"]
    report = original_function_coverage(names, [*rows, row(names[80], "passed")])
    assert report["target_percent"] == 80
    assert report["target_comparison"] == ">"
    assert report["target_met"]


def test_duplicate_original_manifest_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        original_function_coverage(["f", "f"], [])


def test_msc8_report_uses_checked_results_and_complete_original_catalog(tmp_path, monkeypatch) -> None:
    """A conditional checked row cannot inherit raw backend PASS coverage."""
    from argparse import Namespace

    from tools.comparator import msc8_cli
    from tools.dosunit.reporting import flat32_proof_report

    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:100 f proc\n.text:100 f endp\n.text:200 start proc\n.text:200 start endp\n")
    monkeypatch.setattr(flat32_proof_report, "run_bound_comparison",
                        lambda *args: {"results": [row("f", "conditional")]})
    report = msc8_cli.compare(Namespace(oracle_lst=listing, out_dir=tmp_path))
    assert report["original_function_coverage"]["original_functions"] == 2
    assert report["original_function_coverage"]["passed"] == 0
    assert report["original_function_coverage"]["conditional"] == 1
    assert report["original_function_manifest"]["names"] == ["f", "start"]


def test_original_listing_drift_cannot_publish_coverage(tmp_path, monkeypatch) -> None:
    """Changing the denominator while a proof runs must fail visibly."""
    from argparse import Namespace

    from tools.comparator import msc8_cli
    from tools.dosunit.reporting import flat32_proof_report

    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:100 f proc\n.text:100 f endp\n")

    def changed(*args):
        listing.write_text("")
        return {"results": [row("f", "passed")]}

    monkeypatch.setattr(flat32_proof_report, "run_bound_comparison", changed)
    with pytest.raises(RuntimeError, match="listing changed"):
        msc8_cli.compare(Namespace(oracle_lst=listing, out_dir=tmp_path))
