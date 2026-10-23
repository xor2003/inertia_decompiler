"""Renamed globals remain explicit, source-bound relocation premises."""
from pathlib import Path

import pytest


@pytest.mark.parametrize("mutation", ["none", "changed", "missing_declaration", "wrong_address"])
def test_public_renamed_global_premise(tmp_path: Path, mutation: str) -> None:
    from tools.comparator import msc8_cli as driver
    from tools.comparator.tests.test_msc8_driver import _link_map_fixture, _link_map_text

    code = bytes.fromhex("a100304000" + ("40" if mutation == "changed" else "") + "c3")
    args = _link_map_fixture(tmp_path, code)
    args.candidate_link_map = tmp_path / "candidate.map"
    args.candidate_link_map.write_text(_link_map_text(
        " 0002:00000000       _renamed_global            00403000   data.obj\n"))
    source = tmp_path / "aliases.c"
    declaration = "" if mutation == "missing_declaration" else "extern int renamed_global;\n"
    address = "401000" if mutation == "wrong_address" else "402000"
    source.write_text(declaration + f"// {address}: using guessed type int renamed_global;\n")
    args.global_alias_source = source
    report = driver.compare(args)
    row, = report["results"]
    assert row["status"] == ("conditional" if mutation == "none" else "failed"), row
    assert report["auxiliary_inputs"]["global_alias_source"]["path"] == str(source.resolve())
    assert report["input_domain"]["auxiliary_inputs"]["global_alias_source"]["sha256"]


@pytest.mark.parametrize("text, expected", [
    ("extern int renamed;\n// 402000: using guessed type int renamed;\n", {"renamed": 0x402000}),
    ("extern unsigned char renamed[16];\n// 402000: using guessed type unsigned char renamed[16];\n", {"renamed": 0x402000}),
    ("// 402000: using guessed type int renamed;\n", {}),
    ("extern int renamed();\n// 402000: using guessed type int renamed;\n", {}),
    ("extern int renamed;\n// 401000: using guessed type int renamed;\n", {}),
])
def test_source_alias_requires_declaration_and_original_data(tmp_path: Path, text: str, expected: dict[str, int]) -> None:
    from tools.comparator.global_source_aliases import declared_global_aliases

    path = tmp_path / "source.c"
    path.write_text(text)
    assert declared_global_aliases(path, {"dword_402000": 0x402000}) == expected


def test_source_alias_conflict_is_not_last_write_wins(tmp_path: Path) -> None:
    from tools.comparator.global_source_aliases import declared_global_aliases

    path = tmp_path / "source.c"
    path.write_text("extern int renamed;\n// 402000: using guessed type int renamed;\n"
                    "// 402004: using guessed type int renamed;\n")
    with pytest.raises(ValueError, match="conflicting"):
        declared_global_aliases(path, {"dword_402000": 0x402000, "dword_402004": 0x402004})


def test_alias_source_drift_invalidates_public_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.comparator import msc8_cli as driver
    from tools.comparator.tests.test_msc8_driver import _link_map_fixture, _link_map_text

    args = _link_map_fixture(tmp_path, bytes.fromhex("a100304000c3"))
    args.candidate_link_map = tmp_path / "candidate.map"
    args.candidate_link_map.write_text(_link_map_text(
        " 0002:00000000       _renamed_global            00403000   data.obj\n"))
    args.global_alias_source = tmp_path / "aliases.c"
    args.global_alias_source.write_text("extern int renamed_global;\n// 402000: using guessed type int renamed_global;\n")
    original = driver._compare

    def changed(namespace):
        report = original(namespace)
        namespace.global_alias_source.write_text("changed")
        return report

    monkeypatch.setattr(driver, "_compare", changed)
    with pytest.raises(RuntimeError, match="auxiliary input changed"):
        driver.compare(args)


def test_alias_source_requires_verified_link_map(tmp_path: Path) -> None:
    from tools.comparator import msc8_cli as driver
    from tools.comparator.tests.test_msc8_driver import _link_map_fixture

    args = _link_map_fixture(tmp_path, bytes.fromhex("a100304000c3"))
    args.global_alias_source = tmp_path / "aliases.c"
    args.global_alias_source.write_text("extern int renamed;\n// 402000: using guessed type int renamed;\n")
    with pytest.raises(ValueError, match="requires --candidate-link-map"):
        driver.compare(args)
