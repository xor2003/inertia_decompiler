from __future__ import annotations

from pathlib import Path

import pytest

from tools.dev.compare_ghidra_function_coverage import (
    canonical_body_address,
    collect_ghidra_functions,
    compare_coverage,
    inertia_application_calls,
    inertia_function_addresses,
    load_mz_module,
    render_markdown,
)


def _write_mz(path: Path, module: bytes) -> None:
    header_size = 0x20
    image_size = header_size + len(module)
    page_count = (image_size + 511) // 512
    bytes_in_last_page = image_size % 512
    header = bytearray(header_size)
    header[:2] = b"MZ"
    header[2:4] = bytes_in_last_page.to_bytes(2, "little")
    header[4:6] = page_count.to_bytes(2, "little")
    header[8:10] = (header_size // 16).to_bytes(2, "little")
    path.write_bytes(bytes(header) + module)


def test_load_mz_module_excludes_header_and_overlay(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    module = bytes(range(48))
    _write_mz(binary, module)
    binary.write_bytes(binary.read_bytes() + b"overlay")

    assert load_mz_module(binary) == module


def test_canonical_body_address_skips_only_bounded_entry_nops() -> None:
    module = b"\x00" * 13 + b"\x90\x90\x90\x55\x8b\xec"

    assert canonical_body_address(module, 0x100D, image_base=0x1000, maximum_nop_prefix=3) == 0x1010
    with pytest.raises(ValueError, match="NOP-prefix limit"):
        canonical_body_address(module, 0x100D, image_base=0x1000, maximum_nop_prefix=2)


def test_inertia_function_addresses_prefers_whole_file_markers() -> None:
    c_text = """
/* == function 0x1010 sub_1010 == */
int sub_1010(void) { return 0; }
/* == function 0x1020 sub_1020 == */
int sub_1020(void) { return 0; }
"""

    assert inertia_function_addresses(c_text) == (0x1010, 0x1020)


def test_inertia_application_calls_ignore_neighbor_prototypes() -> None:
    c_text = """
/* == function 0x1010 sub_1010 == */
int sub_1020(void);
int sub_1010(void)
{
  return 0;
}
/* == function 0x1020 sub_1020 == */
int sub_1020(void)
{
  return 0;
}
"""

    assert inertia_application_calls(c_text, 0x1010, frozenset((0x1010, 0x1020))) == ()


def test_compare_coverage_filters_to_inertia_application_functions(tmp_path: Path) -> None:
    module = bytearray(b"\xcc" * 0x80)
    module[0x0D:0x11] = b"\x90\x90\x90\x55"
    module[0x40] = 0x55
    ghidra_dir = tmp_path / "ghidra"
    ghidra_dir.mkdir()
    (ghidra_dir / "FUN_0100_000d_0100_000d.c").write_text(
        "void FUN_0100_000d(void) { func_0x00001020(); FUN_0100_0040(); }\n",
        encoding="utf-8",
    )
    (ghidra_dir / "FUN_0100_0040_0100_0040.c").write_text(
        "void FUN_0100_0040(void) {}\n",
        encoding="utf-8",
    )
    inertia_c = """
/* == function 0x1010 sub_1010 == */
int sub_1010(void)
{
  sub_1020();
  return 0;
}
/* == function 0x1020 sub_1020 == */
int sub_1020(void)
{
  return 0;
}
"""
    addresses = frozenset(inertia_function_addresses(inertia_c))
    functions = collect_ghidra_functions(
        ghidra_dir,
        addresses,
        module=bytes(module),
        image_base=0x1000,
        maximum_nop_prefix=8,
    )

    comparison = compare_coverage(inertia_c, functions)

    assert comparison.inertia_function_count == 2
    assert comparison.ghidra_function_count == 2
    assert comparison.matched_function_count == 1
    assert comparison.missing_from_ghidra == (0x1020,)
    assert comparison.functions[0].ghidra_nominal_address == 0x100D
    assert comparison.functions[0].ghidra_nop_prefix_bytes == 3
    assert comparison.functions[0].calls_only_in_inertia == ()
    assert comparison.functions[0].calls_only_in_ghidra == ()
    assert "0x1020" in render_markdown(comparison)
