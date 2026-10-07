"""Loaded executable-section controls for flat32 function catalog admission."""

from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.catalog.flat32_catalog_admission import CatalogRangeStatus, check_function_extent


def _project(*spans: tuple[int, int, bool]) -> SimpleNamespace:
    """Model the CLE section boundary consumed by the admission owner."""
    return SimpleNamespace(loader=SimpleNamespace(main_object=SimpleNamespace(
        sections=[SimpleNamespace(min_addr=left, max_addr=right - 1, is_executable=code)
                  for left, right, code in spans],
    )))


@pytest.mark.parametrize("entry,size,status", [
    (0x1000, 16, CatalogRangeStatus.ADMITTED),
    (0x101F, 1, CatalogRangeStatus.ADMITTED),
    (0x101F, 2, CatalogRangeStatus.EXTENT_OUTSIDE_CODE),
    (0x2000, 1, CatalogRangeStatus.ENTRY_OUTSIDE_CODE),
    (0x1020, 0, CatalogRangeStatus.ENTRY_OUTSIDE_CODE),
    (0x1000, 0, CatalogRangeStatus.ADMITTED),
    (0x1000, -1, CatalogRangeStatus.INVALID_EXTENT),
    (-1, 1, CatalogRangeStatus.INVALID_EXTENT),
    (0xFFFFFFFF, 2, CatalogRangeStatus.INVALID_EXTENT),
    (True, 1, CatalogRangeStatus.INVALID_EXTENT),
    (0x1000, True, CatalogRangeStatus.INVALID_EXTENT),
])
def test_entry_and_extent_require_executable_bytes(entry, size, status) -> None:
    """Neither a mapped data byte nor an envelope crossing a hole is code."""
    project = _project((0x1000, 0x1020, True), (0x2000, 0x2100, False))
    result = check_function_extent(project, entry=entry, size=size)
    assert result.status is status
    assert result.to_document()["executable_ranges"] == [[0x1000, 0x1020]]


def test_contiguous_code_sections_form_one_envelope() -> None:
    """Section order and a contiguous executable boundary do not invent a gap."""
    project = _project((0x1010, 0x1020, True), (0x1000, 0x1010, True))
    result = check_function_extent(project, entry=0x1008, size=24)
    assert result.status is CatalogRangeStatus.ADMITTED
    assert result.executable_ranges == ((0x1000, 0x1020),)


def test_one_byte_hole_between_code_sections_still_refuses() -> None:
    """Executable sections on both sides cannot authorize their unmapped gap."""
    project = _project((0x1000, 0x1010, True), (0x1011, 0x1020, True))
    assert check_function_extent(project, entry=0x1008, size=24).status is CatalogRangeStatus.EXTENT_OUTSIDE_CODE


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("invalid", ["entry", "extent", None])
def test_public_selection_refuses_invalid_pe_envelopes(tmp_path: Path, driver: str, invalid: str | None) -> None:
    """Region admission must not hand unmapped candidate bytes to the scanner."""
    path = tmp_path / "input.exe"
    path.write_bytes(pe32_bytes(b"\xc3"))
    with _driver_lane(driver) as lane:
        project = lane.adapter.load32(path)
        code = next(section for section in project.loader.main_object.sections if section.is_executable)
        entry = code.min_addr if invalid != "entry" else code.max_addr + 1
        size = 1 if invalid != "extent" else code.max_addr - code.min_addr + 2
        symbols = {"f": lane.catalog.Symbol(entry, size, "T")}
        original, candidate, results = lane.z3cmp32.select_functions(
            Namespace(mode="region", scan_limit=0x2000), project, project,
            {"f": (code.min_addr, code.min_addr)}, symbols, ["f"],
        )
    if invalid is None:
        assert results == [] and original and candidate
    else:
        assert original == candidate == {}
        assert len(results) == 1 and results[0]["status"] == "refused"
        expected = (CatalogRangeStatus.ENTRY_OUTSIDE_CODE if invalid == "entry"
                    else CatalogRangeStatus.EXTENT_OUTSIDE_CODE)
        assert results[0]["reason"] == expected.value
        assert results[0]["catalog_admission"]["side"] == "candidate"
