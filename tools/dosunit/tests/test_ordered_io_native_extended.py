"""Native width, port and ordering controls for the declared ordered-I/O model."""

from pathlib import Path

import pytest
import tools.dosunit.tests.test_ordered_io_native as T

pytestmark = [pytest.mark.resource_serial, pytest.mark.xdist_group("ordered-io-native")]


def _compare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: str,
             oracle: bytes, candidate: bytes) -> dict:
    if lane == "real16":
        image_o, catalog_o = T._mz_two_level(oracle)
        image_c, catalog_c = T._mz_two_level(candidate)
        o, c = T._write_mz(tmp_path, image_o, image_c)
        return T._compare16(o, c, catalog_o, catalog_c, bound=True)
    with T._driver_lane(lane) as modules:
        return T._run_driver(modules, tmp_path, T._pe_two_level(oracle),
                             T._pe_two_level(candidate), monkeypatch, bound=True)


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("operation", ["ed", "66ed", "e480", "e680"],
                         ids=["default_word", "override_word", "immediate_in", "immediate_out"])
def test_scalar_io_forms(
    lane: str, operation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scalar widths and immediate IN/OUT retain conditional event equality."""
    code = bytes.fromhex(operation + "31c0c3")
    report = _compare(tmp_path, monkeypatch, lane, code, code)
    if lane == "real16":
        T._assert_conditional_consumed(report)
    else:
        T._assert_row_conditional(T._row(report), report)


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("original,changed", [
    ("ec31c0c3", "ed31c0c3"),
    ("e48031c0c3", "e48131c0c3"),
    ("e480e48131c0c3", "e481e48031c0c3"),
    ("e48031c0c3", "e68031c0c3"),
], ids=["width", "port", "event_order", "immediate_direction"])
def test_event_mutation_is_observable(
    lane: str, original: str, changed: str, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Width, port, and event-order mutations must yield real counterexamples."""
    report = _compare(tmp_path, monkeypatch, lane,
                      bytes.fromhex(original), bytes.fromhex(changed))
    if lane == "real16":
        row = report["proof"]["verdicts"][0]
        assert row["status"] == "counterexample", row
        assert row["detail"] == "observable_mismatch", row
    else:
        row = T._row(report)
        assert row["status"] == "failed", row
        assert row["reason"] == "observable_mismatch", row
